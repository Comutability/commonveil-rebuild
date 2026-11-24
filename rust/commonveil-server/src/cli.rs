//! Admin commands for a self-hosted site (server/cli.mjs), run inside the container:
//!   docker compose exec app commonveil-server <command> [arguments]
//!
//!   make-admin <username>     give an account the admin role (or an older account's email)
//!   reset-password <username> set a temporary password and print it
//!   setup-code                the one-time code for creating a new site's first (admin) account
//!   backup                    copy the database to DATA_DIR/backups
//!   version                   print this site's version
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::config::Config;

fn fail(message: &str) -> i32 {
    eprintln!("{message}");
    1
}

/// Run one command; returns the process exit code.
pub fn run(config: &Config, args: &[String]) -> i32 {
    let (command, arg) = (
        args.first().map(String::as_str).unwrap_or(""),
        args.get(1).cloned().unwrap_or_default(),
    );
    if command == "version" {
        println!("{}", config.version);
        return 0;
    }
    let db = match Connection::open(&config.db_file) {
        Ok(db) => db,
        Err(e) => return fail(&format!("Couldn't open the database: {e}")),
    };
    let record = |entity: &str, id: &str| -> Option<Value> {
        db.query_row(
            "SELECT data FROM records WHERE entity = ? AND id = ?",
            params![entity, id],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .ok()
        .flatten()
        .and_then(|d| serde_json::from_str(&d).ok())
    };
    let save = |entity: &str, id: &str, data: &Value| {
        db.execute(
            "UPDATE records SET data = ? WHERE entity = ? AND id = ?",
            params![data.to_string(), entity, id],
        )
    };
    // The account id for a username.
    let user_id_for = |name: &str| -> Option<String> {
        let n = name.trim().trim_start_matches('@').to_lowercase();
        let p: Option<String> = db.query_row("SELECT data FROM records WHERE entity = 'Profile' AND json_extract(data, '$.username_key') = ? LIMIT 1", [n], |r| r.get(0)).optional().ok().flatten();
        p.and_then(|d| serde_json::from_str::<Value>(&d).ok())
            .and_then(|v| v["user_id"].as_str().map(String::from))
    };
    match command {
        "make-admin" => {
            let id = user_id_for(&arg);
            let table = if id.as_deref().is_some_and(|i| record("Person", i).is_some()) { "Person" } else { "User" };
            let Some((id, mut user)) = id.and_then(|i| record(table, &i).map(|u| (i, u))) else { return fail(&format!("No account for {arg}")) };
            user["role"] = json!("admin");
            if save(table, &id, &user).is_err() {
                return fail("Couldn't save the change.");
            }
            println!("{arg} is now an admin. (Restart the app for it to take effect: docker compose restart app)");
            0
        }
        "reset-password" => {
            let row: Option<(String, String)> = user_id_for(&arg).and_then(|id| {
                db.query_row("SELECT id, data FROM records WHERE entity = 'CvAccount' AND json_extract(data, '$.user_id') = ? LIMIT 1", [id], |r| Ok((r.get(0)?, r.get(1)?))).optional().ok().flatten()
            });
            let Some((row_id, data)) = row else { return fail(&format!("No account for {arg}")) };
            // A one-off password, to be changed after signing in. A new browser still has to be
            // confirmed, and messages still need the recovery phrase or another device.
            let temporary = URL_SAFE_NO_PAD.encode(crate::crypto::random_bytes(12));
            let mut acct: Value = serde_json::from_str(&data).unwrap_or(json!({}));
            let epoch = crate::js::to_number(acct.get("security_epoch"));
            acct["password"] = json!(crate::crypto::hash_password(&temporary, config.password_rounds));
            acct["failed"] = json!(0);
            // Sessions made before this can no longer change how the account is protected.
            acct["security_epoch"] = crate::js::number_value(if epoch.is_nan() { 0.0 } else { epoch } + 1.0);
            if save("CvAccount", &row_id, &acct).is_err() {
                return fail("Couldn't save the change.");
            }
            println!("Give this temporary password to {arg}, once you're sure it's them, and ask them to change it:\n{temporary}\n(Restart the app for it to take effect: docker compose restart app)");
            0
        }
        "setup-code" => {
            let file = config.data_dir.join("setup-code");
            match std::fs::read_to_string(&file) {
                Ok(code) => {
                    println!("{}", code.trim());
                    0
                }
                Err(_) => fail("There's no setup code: this site already has an admin. Use make-admin to add another."),
            }
        }
        "backup" => {
            let dir = config.data_dir.join("backups");
            let _ = std::fs::create_dir_all(&dir);
            let stamp = crate::shared::iso(crate::sessions::now_ms()).replace([':', '.'], "-");
            let file = dir.join(format!("commonveil-{}-{stamp}.db", config.version));
            match db.execute("VACUUM INTO ?", [file.to_string_lossy().as_ref()]) {
                Ok(_) => {
                    println!("Saved {}", file.display());
                    0
                }
                Err(e) => fail(&format!("The backup couldn't be made: {e}")),
            }
        }
        _ => fail(&format!("Unknown command {command}. Try: make-admin, reset-password, setup-code, backup, version")),
    }
}
