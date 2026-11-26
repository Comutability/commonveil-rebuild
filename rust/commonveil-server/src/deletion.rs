//! Deleting an account (base44/shared/accountDeletion.ts). Every record is overwritten with blanks
//! before it's deleted, and the work is ordered so it can stop at any point and be resumed.
use serde_json::{json, Value};

use crate::api::Result;
use crate::db::{id_of, Db};
use crate::js::truthy;
use crate::store::Store;

const PAGE: usize = 100;

/// Ran out of time: call again to continue.
struct OutOfTime;

enum Stop {
    Time,
    Error(crate::api::ApiError),
}
impl From<crate::api::ApiError> for Stop {
    fn from(e: crate::api::ApiError) -> Self {
        Stop::Error(e)
    }
}
impl From<OutOfTime> for Stop {
    fn from(_: OutOfTime) -> Self {
        Stop::Time
    }
}
type R<T> = std::result::Result<T, Stop>;

fn check_time(deadline: i64) -> std::result::Result<(), OutOfTime> {
    if crate::sessions::now_ms() > deadline {
        Err(OutOfTime)
    } else {
        Ok(())
    }
}

/// Blank, then delete, every record matching the query. Returns how many.
fn blank_and_delete_all(
    sr: &Db,
    entity: &str,
    query: Value,
    blank: Value,
    deadline: i64,
) -> R<usize> {
    let mut count = 0;
    loop {
        check_time(deadline)?;
        let rows = sr.filter(entity, query.clone(), "created_date", PAGE)?;
        if rows.is_empty() {
            return Ok(count);
        }
        for row in &rows {
            sr.update(entity, id_of(row), blank.clone())?;
            sr.delete(entity, id_of(row))?;
        }
        count += rows.len();
    }
}

/// Blank and delete every record matching the query: how many, or None if the deadline passed first.
pub fn blank_and_delete_until(
    sr: &Db,
    entity: &str,
    query: Value,
    blank: Value,
    deadline: i64,
) -> Result<Option<usize>> {
    match blank_and_delete_all(sr, entity, query, blank, deadline) {
        Ok(n) => Ok(Some(n)),
        Err(Stop::Time) => Ok(None),
        Err(Stop::Error(e)) => Err(e),
    }
}

pub fn blank(entity: &str) -> Value {
    match entity {
        "Message" => {
            json!({ "conversation_id": "", "msg_id": "", "sender_id": "", "device_id": "", "envelope": "", "signature": "", "sent_at": "", "recipient_ids": [], "deleted": true, "expires_at": "" })
        }
        "Conversation" => {
            json!({ "member_ids": [], "admin_ids": [], "dm_key": "", "creator_id": "", "title_envelope": "", "title_item_id": "", "title_sender_id": "", "title_device_id": "", "title_sent_at": "", "title_signature": "", "last_message_at": "", "expiry_set_by": "", "expiry_set_at": "", "server_id": "", "ticket_channel_id": "", "ticket_opened_by": "" })
        }
        "Block" => json!({ "user_id": "", "blocked_user_id": "" }),
        "Report" => {
            json!({ "reporter_id": "", "reported_user_id": "", "conversation_id": "", "details": "", "resolution_note": "", "handled_by": "" })
        }
        "KeyEnvelope" => {
            json!({ "user_id": "", "device_id": "", "recovery_pub": "", "key_sign_pub": "", "sealed": "", "created_by_device_id": "" })
        }
        "AccountKey" => {
            json!({ "user_id": "", "ecdh_pub": "", "sign_pub": "", "recovery_pub": "", "recovery_mac": "", "signature": "", "issued_at": "", "kem_pub": "", "recovery_kem_pub": "" })
        }
        "ResetRequest" => {
            json!({ "user_id": "", "device_id": "", "device_label": "", "device_sign_pub": "", "device_box_pub": "", "device_kem_pub": "", "statement": "", "cert": "", "recovery_sealed": "", "recovery_pub": "", "key_sign_pub": "", "ended_by": "" })
        }
        "Device" => {
            json!({ "user_id": "", "device_id": "", "label": "", "sign_pub": "", "box_pub": "", "kem_pub": "", "kem_sig": "", "cert_issued_at": "", "cert_signature": "", "approved_by_device_id": "", "approved_at": "", "pending_expires_at": "", "revoked_at": "", "last_seen_at": "" })
        }
        "Profile" => {
            json!({ "user_id": "", "username": "", "username_key": "", "display_name": "", "bio": "", "delete_after_days": 0, "last_active_at": "", "inactive_warned_at": "", "pronouns": "", "accent_color": "", "avatar_emoji": "", "avatar_image": "" })
        }
        _ => json!({}),
    }
}

pub fn is_retired_username(sr: &Db, key: &str) -> Result<bool> {
    Ok(!sr
        .filter(
            "RetiredUsername",
            json!({ "username_key": key }),
            "created_date",
            1,
        )?
        .is_empty())
}

fn retire_username(sr: &Db, key: &str) -> Result<()> {
    if !is_retired_username(sr, key)? {
        sr.create("RetiredUsername", json!({ "username_key": key }))?;
    }
    Ok(())
}

fn erase_conversation(sr: &Db, conversation_id: &str, deadline: i64) -> R<()> {
    blank_and_delete_all(
        sr,
        "Message",
        json!({ "conversation_id": conversation_id }),
        blank("Message"),
        deadline,
    )?;
    sr.update("Conversation", conversation_id, blank("Conversation"))?;
    sr.delete("Conversation", conversation_id)?;
    Ok(())
}

/// Blank and delete a conversation with all its messages. False if the deadline passed first.
pub fn erase_conversation_until(sr: &Db, conversation_id: &str, deadline: i64) -> Result<bool> {
    match erase_conversation(sr, conversation_id, deadline) {
        Ok(()) => Ok(true),
        Err(Stop::Time) => Ok(false),
        Err(Stop::Error(e)) => Err(e),
    }
}

/// Remove everything belonging to `user_id`. True when finished, false if out of time.
pub fn purge_account(sr: &Db, store: &Store, user_id: &str, deadline: i64) -> Result<bool> {
    match purge(sr, store, user_id, deadline) {
        Ok(()) => Ok(true),
        Err(Stop::Time) => Ok(false),
        Err(Stop::Error(e)) => Err(e),
    }
}

fn purge(sr: &Db, store: &Store, user_id: &str, deadline: i64) -> R<()> {
    // 1. Conversations. Direct messages go entirely; groups lose this member.
    loop {
        check_time(deadline)?;
        let convs = sr.filter(
            "Conversation",
            json!({ "member_ids": user_id }),
            "created_date",
            PAGE,
        )?;
        if convs.is_empty() {
            break;
        }
        for c in &convs {
            let (members, admins) = crate::shared::without_member(c, user_id);
            if c["kind"] == "dm" || members.is_empty() {
                erase_conversation(sr, id_of(c), deadline)?;
            } else {
                let mut changes = json!({ "member_ids": members, "admin_ids": admins });
                if c["creator_id"] == user_id {
                    changes["creator_id"] = json!("");
                }
                if c["expiry_set_by"] == user_id {
                    changes["expiry_set_by"] = json!("");
                }
                if c["title_sender_id"] == user_id {
                    for k in [
                        "title_envelope",
                        "title_item_id",
                        "title_sender_id",
                        "title_device_id",
                        "title_sent_at",
                        "title_signature",
                    ] {
                        changes[k] = json!("");
                    }
                }
                sr.update("Conversation", id_of(c), changes)?;
            }
        }
    }
    // 1b. Servers.
    if !crate::servers_core::erase_server_traces(sr, store, user_id, deadline)? {
        return Err(Stop::Time);
    }
    // 2. Everything else the account sent or is named in.
    blank_and_delete_all(
        sr,
        "Message",
        json!({ "sender_id": user_id }),
        blank("Message"),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "ScheduledMessage",
        json!({ "sender_id": user_id }),
        json!({ "envelope": "", "signature": "", "msg_id": "", "recipient_ids": [], "deliver_at": "" }),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "Block",
        json!({ "user_id": user_id }),
        blank("Block"),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "Block",
        json!({ "blocked_user_id": user_id }),
        blank("Block"),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "Report",
        json!({ "reporter_id": user_id }),
        blank("Report"),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "ResetRequest",
        json!({ "user_id": user_id }),
        blank("ResetRequest"),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "ProtoActor",
        json!({ "user_id": user_id }),
        json!({ "user_id": "", "actor_id": "", "handle": "", "document": "", "sealed_account": "" }),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "ProtoPrekey",
        json!({ "user_id": user_id }),
        json!({ "user_id": "", "device": "", "prekey_id": "", "record": "" }),
        deadline,
    )?;
    let mail = json!({ "to_user_id": "", "to_device": "", "from_user_id": "", "envelope": "" });
    blank_and_delete_all(
        sr,
        "ProtoMail",
        json!({ "to_user_id": user_id }),
        mail.clone(),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "ProtoMail",
        json!({ "from_user_id": user_id }),
        mail,
        deadline,
    )?;
    for r in sr.filter(
        "SecurityReport",
        json!({ "reporter_user_id": user_id }),
        "created_date",
        500,
    )? {
        sr.update(
            "SecurityReport",
            id_of(&r),
            json!({ "reporter_user_id": "" }),
        )?;
    }
    // 3. Keys: sealed keyrings, then published keys, then devices.
    blank_and_delete_all(
        sr,
        "KeyEnvelope",
        json!({ "user_id": user_id }),
        blank("KeyEnvelope"),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "AccountKey",
        json!({ "user_id": user_id }),
        blank("AccountKey"),
        deadline,
    )?;
    blank_and_delete_all(
        sr,
        "Device",
        json!({ "user_id": user_id }),
        blank("Device"),
        deadline,
    )?;
    // 4. The profile, after retiring its username.
    loop {
        check_time(deadline)?;
        let profiles = sr.filter(
            "Profile",
            json!({ "user_id": user_id }),
            "created_date",
            PAGE,
        )?;
        if profiles.is_empty() {
            break;
        }
        for p in &profiles {
            if truthy(p.get("username_key")) {
                retire_username(sr, p["username_key"].as_str().unwrap_or(""))?;
            }
            sr.update("Profile", id_of(p), blank("Profile"))?;
            sr.delete("Profile", id_of(p))?;
        }
    }
    Ok(())
}

/// Remove the member's sign-in and account record. Returns whether the record went.
pub fn remove_platform_user(sr: &Db, store: &Store, user_id: &str) -> bool {
    crate::identity::remove_sign_in(store, user_id);
    for name in ["PushSubscription", "PushCode"] {
        for r in sr
            .filter(name, json!({ "user_id": user_id }), "created_date", 200)
            .unwrap_or_default()
        {
            let _ = sr.delete(name, id_of(&r));
        }
    }
    // Which other sites hold what for them, and which sites they use (the federation's own
    // tables; absent if federation never ran here).
    let _: rusqlite::Result<()> = store.with_db(|db| {
        for table in ["fed_claims", "fed_user_hosts"] {
            let exists: bool = db.query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?",
                [table],
                |r| r.get(0),
            )?;
            if exists {
                db.execute(&format!("DELETE FROM {table} WHERE user_id = ?"), [user_id])?;
            }
        }
        Ok(())
    });
    if sr.get("Person", user_id).is_some() {
        sr.delete("Person", user_id).is_ok()
    } else {
        sr.delete("User", user_id).is_ok()
    }
}
