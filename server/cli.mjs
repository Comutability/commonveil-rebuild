// Admin commands for a self-hosted site, run inside the container:
//   docker compose exec app node server/index.mjs <command> [arguments]
//
//   make-admin <username>     give an account the admin role (or an older account's email)
//   reset-password <username> print a one-time link to choose a new password
//   backup                    copy the database to DATA_DIR/backups
//   version                   print this site's version
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export async function runCli(config, [command, arg]) {
  if (command === "version") {
    console.log(config.version);
    return 0;
  }
  const db = new DatabaseSync(config.dbFile);
  const account = (name) => {
    const n = String(name || "").trim().replace(/^@/, "").toLowerCase();
    if (n.includes("@")) return db.prepare("SELECT * FROM auth_accounts WHERE email = ?").get(n);
    const p = db.prepare("SELECT data FROM records WHERE entity = 'Profile' AND json_extract(data, '$.username_key') = ? LIMIT 1").get(n);
    return p ? db.prepare("SELECT * FROM auth_accounts WHERE user_id = ?").get(JSON.parse(p.data).user_id) : null;
  };
  try {
    if (command === "make-admin") {
      const a = account(arg);
      if (!a) return fail(`No account for ${arg}`);
      const row = db.prepare("SELECT data FROM records WHERE entity = 'User' AND id = ?").get(a.user_id);
      const user = JSON.parse(row.data);
      user.role = "admin";
      db.prepare("UPDATE records SET data = ? WHERE entity = 'User' AND id = ?").run(JSON.stringify(user), a.user_id);
      console.log(`${arg} is now an admin. (Restart the app for it to take effect: docker compose restart app)`);
      return 0;
    }
    if (command === "reset-password") {
      const a = account(arg);
      if (!a) return fail(`No account for ${arg}`);
      const t = crypto.randomBytes(32).toString("base64url");
      db.prepare("INSERT INTO auth_codes (email, purpose, code_hash, expires_at, attempts) VALUES (?, 'reset', ?, ?, 0) ON CONFLICT(email, purpose) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at, attempts = 0")
        .run(`user:${a.user_id}`, crypto.createHash("sha256").update(`reset:${t}`).digest("hex"), Date.now() + 3600_000);
      console.log(`Send this link to the account's owner, once you're sure it's them. It works once, for an hour:\n${config.siteUrl}/reset-password?token=${encodeURIComponent(`${t}.${Buffer.from(a.user_id).toString("base64url")}`)}`);
      return 0;
    }
    if (command === "backup") {
      const dir = path.join(config.dataDir, "backups");
      fs.mkdirSync(dir, { recursive: true });
      const file = path.join(dir, `commonveil-${config.version}-${new Date().toISOString().replace(/[:.]/g, "-")}.db`);
      db.exec(`VACUUM INTO '${file.replace(/'/g, "''")}'`);
      console.log(`Saved ${file}`);
      return 0;
    }
    return fail(`Unknown command ${command}. Try: make-admin, reset-password, backup, version`);
  } finally {
    db.close();
  }
}

function fail(message) {
  console.error(message);
  return 1;
}
