//! The first admin of a self-hosted site (docs/SELF_HOSTING.md), as server/bootstrap.mjs.
//!
//! Being the first to sign up proves nothing about who runs a site, so until the site has an
//! admin the server makes a one-time setup code, prints it to its own log and keeps it in
//! DATA_DIR/setup-code (readable only by the server). Creating an account needs that code, and the
//! account it makes is the admin. The code works once; then the file is removed.
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::json;

use crate::store::Store;

const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Default)]
struct State {
    code: Option<String>,
    done: bool,
}

pub struct Bootstrap {
    file: PathBuf,
    state: Mutex<State>,
}

/// `String(s || "").trim().toUpperCase().replace(/[^A-Z0-9]/g, "")`.
fn normal(v: &serde_json::Value) -> String {
    let s = if crate::js::truthy(Some(v)) {
        crate::js::to_js_string(Some(v))
    } else {
        String::new()
    };
    crate::js::trim(&s)
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        .collect()
}

fn grouped(code: &str) -> String {
    code.as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

fn has_admin(s: &Store) -> bool {
    ["Person", "User"].iter().any(|t| {
        s.filter(
            t,
            &json!({ "role": "admin" }),
            Some(&json!("created_date")),
            Some(1.0),
            None,
        )
        .is_ok_and(|r| !r.is_empty())
    })
}

impl Bootstrap {
    pub fn new(data_dir: &std::path::Path) -> Self {
        Self {
            file: data_dir.join("setup-code"),
            state: Mutex::new(State::default()),
        }
    }

    fn finish(&self, st: &mut State) {
        st.done = true;
        st.code = None;
        let _ = std::fs::remove_file(&self.file);
    }

    /// At start-up: make and show a code if the site has no admin yet.
    pub fn prepare(&self, s: &Store) {
        let mut st = self.state.lock().unwrap();
        if has_admin(s) {
            return self.finish(&mut st);
        }
        // 20 characters from a 32-letter alphabet: 100 bits, written in groups of five.
        let code: String = crate::crypto::random_bytes(20)
            .iter()
            .map(|b| ALPHABET[(b % 32) as usize] as char)
            .collect();
        let shown = grouped(&code);
        let _ = std::fs::create_dir_all(self.file.parent().unwrap_or(std::path::Path::new(".")));
        let written = {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            o.open(&self.file)
                .and_then(|mut f| f.write_all(format!("{shown}\n").as_bytes()))
        };
        if written.is_err() {
            eprintln!(
                "Couldn't write {}; the setup code is only in this log.",
                self.file.display()
            );
        }
        println!("This site has no admin yet. Create the first account with this setup code (also in {}):\n\n    {shown}\n", self.file.display());
        st.code = Some(code);
    }

    /// Whether creating an account needs the code (and makes an admin).
    pub fn needed(&self, s: &Store) -> bool {
        let mut st = self.state.lock().unwrap();
        if st.done {
            return false;
        }
        if has_admin(s) {
            self.finish(&mut st);
            return false;
        }
        st.code.is_some()
    }

    /// Use the code: true once, for the right code; false for anything else.
    pub fn consume(&self, given: &serde_json::Value) -> bool {
        let mut st = self.state.lock().unwrap();
        let Some(code) = st.code.clone().filter(|_| !st.done) else {
            return false;
        };
        if !crate::crypto::same_string(&normal(given), &code) {
            return false;
        }
        self.finish(&mut st);
        true
    }

    pub fn pending(&self) -> bool {
        let st = self.state.lock().unwrap();
        st.code.is_some() && !st.done
    }
}
