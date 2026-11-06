// Admin commands for a self-hosted site, run inside the container:
//   docker compose exec app node server/index.mjs <command> [arguments]
//
//   make-admin <username>     give an account the admin role (or an older account's email)
//   reset-password <username> set a temporary password and print it
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
  const record = (entity, id) => {
    const row = db.prepare("SELECT data FROM records WHERE entity = ? AND id = ?").get(entity, id);
    return row ? JSON.parse(row.data) : null;
  };
  const save = (entity, id, data) => db.prepare("UPDATE records SET data = ? WHERE entity = ? AND id = ?").run(JSON.stringify(data), entity, id);
  /** The account id for a username. */
  const userIdFor = (name) => {
    const n = String(name || "").trim().replace(/^@/, "").toLowerCase();
    const p = db.prepare("SELECT data FROM records WHERE entity = 'Profile' AND json_extract(data, '$.username_key') = ? LIMIT 1").get(n);
    return p ? JSON.parse(p.data).user_id : null;
  };
  try {
    if (command === "make-admin") {
      const id = userIdFor(arg);
      const table = id && record("Person", id) ? "Person" : "User";
      const user = id && record(table, id);
      if (!user) return fail(`No account for ${arg}`);
      save(table, id, { ...user, role: "admin" });
      console.log(`${arg} is now an admin. (Restart the app for it to take effect: docker compose restart app)`);
      return 0;
    }
    if (command === "reset-password") {
      const id = userIdFor(arg);
      const row = id && db.prepare("SELECT id, data FROM records WHERE entity = 'CvAccount' AND json_extract(data, '$.user_id') = ? LIMIT 1").get(id);
      if (!row) return fail(`No account for ${arg}`);
      // A one-off password, to be changed after signing in. A new browser still has to be confirmed,
      // and messages still need the person's recovery phrase or another of their devices.
      const temporary = crypto.randomBytes(12).toString("base64url");
      const { hashPassword } = await import("../base44/shared/identity/crypto.ts");
      save("CvAccount", row.id, { ...JSON.parse(row.data), password: await hashPassword(temporary, config.passwordRounds), failed: 0 });
      console.log(`Give this temporary password to ${arg}, once you're sure it's them, and ask them to change it:\n${temporary}\n(Restart the app for it to take effect: docker compose restart app)`);
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
