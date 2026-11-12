// The first admin of a self-hosted site (docs/SELF_HOSTING.md).
//
// Being the first to sign up, or picking a particular username, proves nothing about who runs a
// site: anyone could reach a new install before its operator. So until the site has an admin, the
// server makes a one-time setup code, prints it to its own log and keeps it in DATA_DIR/setup-code
// (readable only by the server). Creating an account needs that code, and the account it makes is
// the admin. The code works once; then the file is removed and sign-up follows OPEN_REGISTRATION.
// An operator can also make anyone an admin from the command line (make-admin).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const normal = (s) => String(s || "").trim().toUpperCase().replace(/[^A-Z0-9]/g, "");

export function createBootstrap({ dataDir, log = console }) {
  const file = path.join(dataDir, "setup-code");
  let code = null;
  let done = false;

  const finish = () => {
    done = true;
    code = null;
    try {
      fs.rmSync(file, { force: true });
    } catch {
      // Nothing to remove.
    }
  };

  async function hasAdmin(sr) {
    const people = await sr.entities.Person.filter({ role: "admin" }, "created_date", 1).catch(() => []);
    if (people.length) return true;
    const users = await sr.entities.User.filter({ role: "admin" }, "created_date", 1).catch(() => []);
    return users.length > 0;
  }

  return {
    /** At start-up: make and show a code if the site has no admin yet. */
    async prepare(sr) {
      if (await hasAdmin(sr)) return finish();
      // 20 characters from a 32-letter alphabet: 100 bits, written in groups of five.
      const raw = crypto.randomBytes(20);
      const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      code = Array.from(raw, (b) => alphabet[b % 32]).join("");
      fs.writeFileSync(file, `${code.match(/.{5}/g).join("-")}\n`, { mode: 0o600 });
      log.info?.(`This site has no admin yet. Create the first account with this setup code (also in ${file}):\n\n    ${code.match(/.{5}/g).join("-")}\n`);
    },
    /** Whether creating an account needs the code (and makes an admin). */
    async needed(sr) {
      if (done) return false;
      if (await hasAdmin(sr)) {
        finish();
        return false;
      }
      return Boolean(code);
    },
    /** Use the code: true once, for the right code; false for anything else. */
    consume(given) {
      if (done || !code) return false;
      const a = Buffer.from(normal(given));
      const b = Buffer.from(code);
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
      finish();
      return true;
    },
    get pending() {
      return Boolean(code) && !done;
    },
  };
}
