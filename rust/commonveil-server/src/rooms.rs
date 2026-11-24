//! The realtime rooms (base44/actors): Presence and VoiceRoom.
//!
//! Presence: who's here right now, and who's typing, for people who chose to share it. One room
//! per server ("s.<serverId>") or conversation ("c.<conversationId>"); only its members get in.
//! Nothing is written down: it lives in memory while people are connected.
//!
//! VoiceRoom: one call's connection set-up (WebRTC offers, answers and candidates) between the
//! devices in it, plus who's muted. Audio never comes here: it goes directly between devices,
//! encrypted twice. A connection gets in with a single-use pass from the voice function.
use std::collections::HashMap;

use serde_json::{json, Value};

use crate::actors::{Cx, Room};
use crate::db::Db;
use crate::js::{to_js_string, to_number, truthy};

fn now() -> i64 {
    crate::sessions::now_ms()
}

fn id_ok(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

fn str_id(v: &Value) -> Option<String> {
    v.as_str().filter(|s| id_ok(s, 8, 64)).map(String::from)
}

/// The access-token sign-in both rooms take: `{ type: "__auth", token }`.
#[derive(Default)]
struct SignIn(HashMap<String, String>);

impl SignIn {
    /// The account a connection speaks for: the platform's, or the one it signed in as.
    fn user(&self, cx: &Cx, conn_id: &str) -> Option<String> {
        let c = cx.conn(conn_id)?;
        c.user_id.clone().or_else(|| self.0.get(conn_id).cloned())
    }
    fn sign_in(&mut self, cx: &Cx, conn_id: &str, msg: &Value) -> bool {
        let Some(c) = cx.conn(conn_id) else {
            return false;
        };
        if c.user_id.is_some() {
            return true;
        }
        match crate::sessions::verify_access(&cx.app.keys, &cx.app.store, msg.get("token"), now()) {
            Some(s) => {
                self.0.insert(conn_id.to_string(), s.user_id);
                true
            }
            None => {
                c.reject(4003, "Please sign in again.");
                false
            }
        }
    }
}

/// Messages per connection in ten seconds before the rest are ignored.
#[derive(Default)]
struct Flood(HashMap<String, (i64, u32)>);

impl Flood {
    fn flooding(&mut self, conn_id: &str, max: u32) -> bool {
        let t = now();
        let e = self.0.entry(conn_id.to_string()).or_insert((t, 0));
        if t - e.0 > 10_000 {
            *e = (t, 0);
        }
        e.1 += 1;
        e.1 > max
    }
}

/// An insertion-ordered map by connection id, as JavaScript's Map.
struct Ordered<T>(Vec<(String, T)>);

impl<T> Default for Ordered<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> Ordered<T> {
    fn get(&self, k: &str) -> Option<&T> {
        self.0.iter().find(|(id, _)| id == k).map(|(_, v)| v)
    }
    fn get_mut(&mut self, k: &str) -> Option<&mut T> {
        self.0.iter_mut().find(|(id, _)| id == k).map(|(_, v)| v)
    }
    fn has(&self, k: &str) -> bool {
        self.get(k).is_some()
    }
    fn set(&mut self, k: &str, v: T) {
        match self.get_mut(k) {
            Some(x) => *x = v,
            None => self.0.push((k.to_string(), v)),
        }
    }
    fn delete(&mut self, k: &str) -> Option<T> {
        let pos = self.0.iter().position(|(id, _)| id == k)?;
        Some(self.0.remove(pos).1)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

// ---------- Presence ----------

const PRESENCE_MAX_PEOPLE: usize = 400;
const PRESENCE_RECHECK_MS: i64 = 5 * 60_000;
const TYPING_EVERY_MS: i64 = 2500;
const PRESENCE_MESSAGES_PER_10S: u32 = 30;

#[derive(Clone)]
struct Here {
    user_id: String,
    status: String,
    checked_at: i64,
    typed_at: i64,
}

#[derive(Default)]
pub struct Presence {
    people: Ordered<Here>,
    flood: Flood,
    signed_in: SignIn,
}

impl Presence {
    /// ("s" | "c", id) from "s.<id>" or "c.<id>".
    fn room(cx: &Cx) -> Option<(char, String)> {
        let (kind, id) = cx.instance_id.split_once('.')?;
        let k = match kind {
            "s" => 's',
            "c" => 'c',
            _ => return None,
        };
        id_ok(id, 8, 64).then(|| (k, id.to_string()))
    }

    fn is_member(cx: &Cx, user_id: &str) -> bool {
        let Some((kind, id)) = Self::room(cx) else {
            return false;
        };
        let sr = Db::service(&cx.app.store);
        if kind == 's' {
            return sr
                .first(
                    "ServerMember",
                    json!({ "server_id": id, "user_id": user_id }),
                    "created_date",
                )
                .ok()
                .flatten()
                .is_some();
        }
        sr.get("Conversation", &id).is_some_and(|c| {
            crate::shared::ids_of(&c["member_ids"])
                .iter()
                .any(|m| m == user_id)
        })
    }

    fn admit(&mut self, cx: &Cx, conn_id: &str) -> Option<Here> {
        let user = self.signed_in.user(cx, conn_id)?;
        let known = self.people.get(conn_id).cloned();
        if let Some(k) = &known {
            if k.user_id == user && now() - k.checked_at < PRESENCE_RECHECK_MS {
                return known;
            }
        }
        if !Self::is_member(cx, &user) {
            self.people.delete(conn_id);
            if let Some(c) = cx.conn(conn_id) {
                c.reject(4003, "Not a member.");
            }
            return None;
        }
        let entry = match known.as_ref().filter(|k| k.user_id == user) {
            Some(k) => Here {
                checked_at: now(),
                ..k.clone()
            },
            None => Here {
                user_id: user,
                status: "online".into(),
                checked_at: now(),
                typed_at: 0,
            },
        };
        if known.is_none() && self.people.len() >= PRESENCE_MAX_PEOPLE {
            if let Some(c) = cx.conn(conn_id) {
                c.reject(4001, "Too many people here to show presence.");
            }
            return None;
        }
        self.people.set(conn_id, entry.clone());
        Some(entry)
    }

    /// One entry per person (they may be here on several devices): online beats idle.
    fn list(&self) -> Value {
        let mut by: Ordered<String> = Ordered::default();
        for (_, p) in &self.people.0 {
            if !by.has(&p.user_id) || p.status == "online" {
                by.set(&p.user_id, p.status.clone());
            }
        }
        json!(by
            .0
            .iter()
            .map(|(u, s)| json!({ "user_id": u, "status": s }))
            .collect::<Vec<_>>())
    }

    fn broadcast_people(&self, cx: &Cx) {
        let msg = json!({ "type": "here", "people": self.list() });
        for c in cx.conns.iter().filter(|c| self.people.has(&c.id)) {
            c.send(&msg);
        }
    }
}

impl Room for Presence {
    fn start(&mut self, _cx: &mut Cx) {
        self.people = Ordered::default();
    }

    fn connect(&mut self, cx: &mut Cx, conn_id: &str) {
        if self.signed_in.user(cx, conn_id).is_none() {
            if let Some(c) = cx.conn(conn_id) {
                c.send(&json!({ "type": "sign-in-needed" }));
            }
            return;
        }
        if self.admit(cx, conn_id).is_none() {
            return;
        }
        if let Some(c) = cx.conn(conn_id) {
            c.send(&json!({ "type": "here", "people": self.list() }));
        }
        self.broadcast_people(cx);
    }

    fn message(&mut self, cx: &mut Cx, conn_id: &str, msg: &Value) {
        if !msg.is_object()
            || !msg["type"].is_string()
            || self.flood.flooding(conn_id, PRESENCE_MESSAGES_PER_10S)
        {
            return;
        }
        if msg["type"] == "__auth" {
            if self.signed_in.sign_in(cx, conn_id, msg) {
                self.connect(cx, conn_id);
            }
            return;
        }
        let fresh = !self.people.has(conn_id);
        let Some(me) = self.admit(cx, conn_id) else {
            return;
        };
        if msg["type"] == "hello" {
            let status = msg["status"]
                .as_str()
                .filter(|s| *s == "online" || *s == "idle")
                .unwrap_or("online")
                .to_string();
            let changed = fresh || status != me.status;
            if let Some(p) = self.people.get_mut(conn_id) {
                p.status = status;
            }
            if fresh {
                if let Some(c) = cx.conn(conn_id) {
                    c.send(&json!({ "type": "here", "people": self.list() }));
                }
            }
            if changed {
                self.broadcast_people(cx);
            }
        } else if msg["type"] == "typing" {
            // Where: a channel id in a server, nothing in a conversation. Throttled.
            let channel = if Self::room(cx).is_some_and(|(k, _)| k == 's') {
                str_id(&msg["channel_id"])
            } else {
                Some(String::new())
            };
            let Some(channel) = channel else { return };
            if now() - me.typed_at < TYPING_EVERY_MS {
                return;
            }
            if let Some(p) = self.people.get_mut(conn_id) {
                p.typed_at = now();
            }
            let thread = str_id(&msg["thread_id"]).unwrap_or_default();
            let out = json!({ "type": "typing", "user_id": me.user_id, "channel_id": channel, "thread_id": thread });
            for c in cx
                .conns
                .iter()
                .filter(|c| c.id != conn_id && self.people.has(&c.id))
            {
                c.send(&out);
            }
        }
    }

    fn close(&mut self, cx: &mut Cx, conn_id: &str) {
        self.flood.0.remove(conn_id);
        self.signed_in.0.remove(conn_id);
        if self.people.delete(conn_id).is_some() {
            self.broadcast_people(cx);
        }
    }

    fn wake(&mut self, _cx: &mut Cx, _key: &str) {}
}

// ---------- VoiceRoom ----------

const VOICE_MAX_PEOPLE: i64 = 8;
const VOICE_MAX_STAGE: i64 = 16;
const GRACE_MS: i64 = 20_000;
const VOICE_RECHECK_MS: i64 = 60_000;
const MAX_SIGNAL_CHARS: usize = 24_000;
const VOICE_MESSAGES_PER_10S: u32 = 200;

fn clean_hello(h: &Value) -> Option<Value> {
    if !h.is_object() {
        return None;
    }
    let call_id = str_id(&h["call_id"])?;
    let fp = h["fingerprint"].as_str().filter(|f| {
        let parts: Vec<&str> = f.split(':').collect();
        parts.len() == 32
            && parts.iter().all(|p| {
                p.len() == 2
                    && p.bytes()
                        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
            })
    })?;
    let issued = h["issued_at"]
        .as_str()
        .filter(|s| s.encode_utf16().count() <= 40)?;
    let sig = h["signature"].as_str().filter(|s| {
        (1..=400).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
    })?;
    // Every part must be there (an empty issued_at counts as missing, as `&&` does in JavaScript).
    if issued.is_empty() {
        return None;
    }
    Some(json!({ "call_id": call_id, "fingerprint": fp, "issued_at": issued, "signature": sig }))
}

/// Everyone in the call, by connection id, in the JavaScript shape that's saved:
/// `{ seat, userId, deviceId, hello, canSpeak, canModerate, stage, hand, muted, deafened, goneAt?, modMuted? }`.
#[derive(Default)]
pub struct VoiceRoom {
    people: Ordered<Value>,
    next_seat: i64,
    flood: Flood,
    signed_in: SignIn,
}

fn b(v: &Value, k: &str) -> bool {
    truthy(v.get(k))
}

impl VoiceRoom {
    fn save(&self, cx: &Cx) {
        cx.storage_put(
            "people",
            &json!(self
                .people
                .0
                .iter()
                .map(|(id, p)| json!([id, p]))
                .collect::<Vec<_>>()),
        );
    }

    fn public_of(p: &Value) -> Value {
        json!({
            "seat": p["seat"], "user_id": p["userId"], "device_id": p["deviceId"], "hello": p["hello"], "muted": p["muted"], "deafened": p["deafened"],
            "can_speak": p["canSpeak"] != false, "moderator": b(p, "canModerate"), "hand": b(p, "hand"), "mod_muted": b(p, "modMuted"),
        })
    }

    fn send_to_members(&self, cx: &Cx, data: &Value, except: Option<&str>) {
        for c in cx
            .conns
            .iter()
            .filter(|c| Some(c.id.as_str()) != except && self.people.has(&c.id))
        {
            c.send(data);
        }
    }

    fn broadcast_state(&self, cx: &Cx, p: &Value) {
        self.send_to_members(cx, &json!({ "type": "peer-state", "seat": p["seat"], "muted": p["muted"], "deafened": p["deafened"], "can_speak": p["canSpeak"] != false, "hand": b(p, "hand"), "mod_muted": b(p, "modMuted") }), None);
    }

    fn welcome(&self, cx: &Cx, conn_id: &str, me: &Value) {
        let peers: Vec<Value> = self
            .people
            .0
            .iter()
            .filter(|(id, _)| id != conn_id)
            .map(|(_, p)| Self::public_of(p))
            .collect();
        let stage = b(me, "stage");
        if let Some(c) = cx.conn(conn_id) {
            c.send(&json!({ "type": "welcome", "seat": me["seat"], "can_speak": me["canSpeak"], "can_moderate": b(me, "canModerate"), "stage": stage, "peers": peers, "max_people": if stage { VOICE_MAX_STAGE } else { VOICE_MAX_PEOPLE } }));
        }
    }

    fn remove(&mut self, cx: &Cx, conn_id: &str) {
        let Some(p) = self.people.delete(conn_id) else {
            return;
        };
        self.save(cx);
        self.send_to_members(cx, &json!({ "type": "peer-left", "seat": p["seat"] }), None);
    }

    fn seat_of(v: &Value) -> f64 {
        to_number(Some(v))
    }

    /// Still a member (and not timed out), or still in the conversation. Fails closed.
    fn still_allowed(cx: &Cx, user_id: &str) -> bool {
        let room = cx.instance_id;
        let sr = Db::service(&cx.app.store);
        let parts: Vec<&str> = room.split('.').collect();
        if parts.len() == 3 && parts[0] == "dm" && id_ok(parts[1], 8, 64) && id_ok(parts[2], 8, 32)
        {
            return sr.get("Conversation", parts[1]).is_some_and(|c| {
                crate::shared::ids_of(&c["member_ids"])
                    .iter()
                    .any(|m| m == user_id)
            });
        }
        if parts.len() != 2 || !id_ok(parts[0], 8, 64) || !id_ok(parts[1], 8, 64) {
            return false;
        }
        match sr.first(
            "ServerMember",
            json!({ "server_id": parts[0], "user_id": user_id }),
            "created_date",
        ) {
            Ok(Some(m)) => {
                !(truthy(m.get("timeout_until"))
                    && crate::dates::parse(&to_js_string(m.get("timeout_until")))
                        .unwrap_or(f64::NAN)
                        > now() as f64)
            }
            _ => false,
        }
    }

    fn recheck(&mut self, cx: &mut Cx) {
        let mut users: HashMap<String, bool> = HashMap::new();
        let snapshot: Vec<(String, String)> = self
            .people
            .0
            .iter()
            .map(|(id, p)| (id.clone(), to_js_string(p.get("userId"))))
            .collect();
        for (id, user) in snapshot {
            let ok = *users
                .entry(user.clone())
                .or_insert_with(|| Self::still_allowed(cx, &user));
            if ok {
                continue;
            }
            self.remove(cx, &id);
            if let Some(c) = cx.conn(&id) {
                c.reject(4006, "You're no longer allowed in this call.");
            }
        }
        if self.people.len() > 0 {
            cx.schedule("recheck", now() + VOICE_RECHECK_MS);
        }
    }

    fn join(&mut self, cx: &mut Cx, conn_id: &str, user: Option<String>, msg: &Value) {
        let Some(c) = cx.conn(conn_id) else { return };
        let Some(user_id) = user else {
            c.reject(4003, "Sign in to join calls.");
            return;
        };
        if let Some(existing) = self.people.get(conn_id).cloned() {
            self.welcome(cx, conn_id, &existing);
            return;
        }
        let ticket_id = str_id(&msg["ticket"]);
        let hello = clean_hello(&msg["hello"]);
        let (Some(ticket_id), Some(hello)) = (ticket_id, hello) else {
            c.send(&json!({ "type": "error", "code": "BAD_JOIN", "message": "That join request isn't valid." }));
            return;
        };
        let sr = Db::service(&cx.app.store);
        let ticket = sr.get("VoiceTicket", &ticket_id);
        let valid = ticket.as_ref().is_some_and(|t| {
            t["room"] == cx.instance_id
                && t["user_id"] == user_id.as_str()
                && crate::dates::parse(&to_js_string(t.get("expires_at"))).unwrap_or(f64::NAN)
                    > now() as f64
        });
        if ticket.is_some() && sr.delete("VoiceTicket", &ticket_id).is_err() {
            // Single use, valid or not. Already gone: someone else used it first.
            c.send(&json!({ "type": "error", "code": "PASS_USED", "message": "That pass was already used. Try joining again." }));
            return;
        }
        let Some(ticket) = ticket.filter(|_| valid) else {
            c.send(&json!({ "type": "error", "code": "PASS_INVALID", "message": "Your pass for this call has expired. Try joining again." }));
            return;
        };
        // The same device joining again (a reload, say) replaces its old place, connected or not.
        let replaced: Vec<String> = self
            .people
            .0
            .iter()
            .filter(|(id, p)| {
                id != conn_id
                    && p["userId"] == user_id.as_str()
                    && p["deviceId"] == ticket["device_id"]
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in replaced {
            self.remove(cx, &id);
            cx.cancel(&format!("drop:{id}"));
            if let Some(old) = cx.conn(&id) {
                old.reject(4005, "You joined this call from somewhere else.");
            }
        }
        let stage = ticket["stage"] == true;
        let max = if stage {
            VOICE_MAX_STAGE
        } else {
            VOICE_MAX_PEOPLE
        };
        if self.people.len() as i64 >= max {
            if let Some(c) = cx.conn(conn_id) {
                c.send(&json!({ "type": "error", "code": "CALL_FULL", "message": format!("This call is full: up to {max} people can be in it.") }));
            }
            return;
        }
        let seat = self.next_seat;
        self.next_seat += 1;
        let me = json!({
            "seat": seat, "userId": user_id, "deviceId": ticket["device_id"], "hello": hello,
            "canSpeak": ticket["can_speak"] != false, "canModerate": ticket["can_moderate"] == true, "stage": stage, "hand": false,
            "muted": b(msg, "muted") || ticket["can_speak"] == false, "deafened": b(msg, "deafened"),
        });
        self.people.set(conn_id, me.clone());
        self.save(cx);
        if self.people.len() == 1 {
            cx.schedule("recheck", now() + VOICE_RECHECK_MS);
        }
        self.welcome(cx, conn_id, &me);
        self.send_to_members(
            cx,
            &json!({ "type": "peer-joined", "peer": Self::public_of(&me) }),
            Some(conn_id),
        );
    }
}

impl Room for VoiceRoom {
    fn start(&mut self, cx: &mut Cx) {
        // Any wake: reload who's in the call, then drop anyone whose connection is gone.
        if let Some(saved) = cx.storage_get("people") {
            self.people = Ordered(
                saved
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| Some((e[0].as_str()?.to_string(), e[1].clone())))
                    .collect(),
            );
        }
        let mut changed = false;
        let ids: Vec<String> = self.people.0.iter().map(|(id, _)| id.clone()).collect();
        for id in ids {
            if cx.conn(&id).is_some() {
                continue;
            }
            let gone = self
                .people
                .get(&id)
                .and_then(|p| p.get("goneAt"))
                .map(|g| to_number(Some(g)));
            match gone {
                None => {
                    let t = now();
                    if let Some(p) = self.people.get_mut(&id) {
                        p["goneAt"] = json!(t);
                    }
                    cx.schedule(&format!("drop:{id}"), t + GRACE_MS);
                    changed = true;
                }
                Some(g) if now() as f64 - g > GRACE_MS as f64 => {
                    self.people.delete(&id);
                    changed = true;
                }
                _ => {}
            }
        }
        self.next_seat = self
            .people
            .0
            .iter()
            .map(|(_, p)| Self::seat_of(&p["seat"]) as i64)
            .fold(0, i64::max)
            + 1;
        if changed {
            self.save(cx);
        }
    }

    fn connect(&mut self, cx: &mut Cx, conn_id: &str) {
        let Some(user) = self.signed_in.user(cx, conn_id) else {
            if let Some(c) = cx.conn(conn_id) {
                c.send(&json!({ "type": "sign-in-needed" }));
            }
            return;
        };
        if let Some(me) = self
            .people
            .get(conn_id)
            .cloned()
            .filter(|m| m["userId"] == user.as_str())
        {
            // A reconnect of someone already in: same place, if they're still allowed.
            if !Self::still_allowed(cx, &user) {
                self.remove(cx, conn_id);
                if let Some(c) = cx.conn(conn_id) {
                    c.reject(4006, "You're no longer allowed in this call.");
                }
                return;
            }
            let mut me = me;
            if me.get("goneAt").is_some() {
                if let Some(p) = self.people.get_mut(conn_id) {
                    p.as_object_mut().map(|o| o.remove("goneAt"));
                    me = p.clone();
                }
                cx.cancel(&format!("drop:{conn_id}"));
                self.save(cx);
            }
            self.welcome(cx, conn_id, &me);
            return;
        }
        if let Some(c) = cx.conn(conn_id) {
            c.send(&json!({ "type": "pass-needed" }));
        }
    }

    fn message(&mut self, cx: &mut Cx, conn_id: &str, msg: &Value) {
        if !msg.is_object()
            || !msg["type"].is_string()
            || self.flood.flooding(conn_id, VOICE_MESSAGES_PER_10S)
        {
            return;
        }
        if msg["type"] == "__auth" {
            if self.signed_in.sign_in(cx, conn_id, msg) {
                self.connect(cx, conn_id);
            }
            return;
        }
        let user = self.signed_in.user(cx, conn_id);
        if msg["type"] == "join" {
            self.join(cx, conn_id, user, msg);
            return;
        }
        // A connection id is chosen by the app: it only ever speaks for the account let in with it.
        let Some(me) = self.people.get(conn_id).cloned() else {
            return;
        };
        if user.as_deref() != me["userId"].as_str() {
            return;
        }
        let kind = msg["type"].as_str().unwrap_or("");
        match kind {
            "signal" => {
                let to = to_number(msg.get("to"));
                let target = cx.conns.iter().find(|c| {
                    self.people
                        .get(&c.id)
                        .is_some_and(|p| Self::seat_of(&p["seat"]) == to)
                });
                let Some(target) = target.filter(|t| t.id != conn_id) else {
                    return;
                };
                let data = msg.get("data").cloned().unwrap_or(Value::Null);
                if crate::protocol::js_stringify(&data).encode_utf16().count() > MAX_SIGNAL_CHARS {
                    return;
                }
                let mut out = json!({ "type": "signal", "from": me["seat"] });
                if let Some(d) = msg.get("data") {
                    out["data"] = d.clone();
                }
                target.send(&out);
            }
            "state" => {
                let p = self.people.get_mut(conn_id).expect("present");
                p["muted"] = json!(b(msg, "muted") || p["canSpeak"] == false || b(p, "modMuted"));
                p["deafened"] = json!(b(msg, "deafened"));
                let p = p.clone();
                self.save(cx);
                self.broadcast_state(cx, &p);
            }
            "leave" => self.remove(cx, conn_id),
            "hand" if b(&me, "stage") => {
                let p = self.people.get_mut(conn_id).expect("present");
                p["hand"] = json!(b(msg, "raised") && p["canSpeak"] == false);
                let p = p.clone();
                self.save(cx);
                self.broadcast_state(cx, &p);
            }
            "set-speaker" | "mute-peer" | "unmute-peer"
                if b(&me, "canModerate") && (kind != "set-speaker" || b(&me, "stage")) =>
            {
                let seat = to_number(msg.get("seat"));
                let Some(target_id) = self
                    .people
                    .0
                    .iter()
                    .find(|(_, p)| Self::seat_of(&p["seat"]) == seat)
                    .map(|(id, _)| id.clone())
                else {
                    return;
                };
                let t = self.people.get_mut(&target_id).expect("present");
                match kind {
                    "set-speaker" => {
                        t["canSpeak"] = json!(b(msg, "speak"));
                        t["hand"] = json!(false);
                        t["modMuted"] = json!(false);
                        if t["canSpeak"] == false {
                            t["muted"] = json!(true);
                        }
                    }
                    "mute-peer" => {
                        // A moderator's mute holds until a moderator lifts it.
                        t["modMuted"] = json!(true);
                        t["muted"] = json!(true);
                    }
                    _ => t["modMuted"] = json!(false),
                }
                let t = t.clone();
                self.save(cx);
                self.broadcast_state(cx, &t);
            }
            _ => {}
        }
    }

    fn close(&mut self, cx: &mut Cx, conn_id: &str) {
        self.flood.0.remove(conn_id);
        self.signed_in.0.remove(conn_id);
        let left = match self.people.get(conn_id) {
            None => true,
            Some(p) => b(p, "left"),
        };
        if left {
            self.remove(cx, conn_id);
            return;
        }
        let t = now();
        if let Some(p) = self.people.get_mut(conn_id) {
            p["goneAt"] = json!(t);
        }
        self.save(cx);
        cx.schedule(&format!("drop:{conn_id}"), t + GRACE_MS);
    }

    fn wake(&mut self, cx: &mut Cx, key: &str) {
        if key == "recheck" {
            self.recheck(cx);
            return;
        }
        let Some(id) = key.strip_prefix("drop:") else {
            return;
        };
        if !self
            .people
            .get(id)
            .is_some_and(|p| p.get("goneAt").is_some())
        {
            return;
        }
        if cx.conn(id).is_some() {
            if let Some(p) = self.people.get_mut(id) {
                p.as_object_mut().map(|o| o.remove("goneAt"));
            }
            self.save(cx);
            return;
        }
        self.remove(cx, id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hellos_need_every_part() {
        let fp = vec!["AB"; 32].join(":");
        let ok = json!({ "call_id": "abcdefgh12", "fingerprint": fp, "issued_at": "2026-01-01T00:00:00Z", "signature": "c2ln" });
        assert!(clean_hello(&ok).is_some());
        for (k, v) in [
            ("call_id", json!("short")),
            ("fingerprint", json!("ab:cd")),
            ("issued_at", json!("")),
            ("signature", json!("not base64!")),
        ] {
            let mut bad = ok.clone();
            bad[k] = v;
            assert!(clean_hello(&bad).is_none(), "{k}");
        }
    }
}
