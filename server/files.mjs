// Private file storage for a self-hosted site. Files are already end-to-end encrypted parts when
// they arrive; this keeps them on disk and hands out short-lived signed links, like Base44's
// UploadPrivateFile and CreateFileSignedUrl.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const URI_RE = /^private:\/\/([a-f0-9]{48})$/;

export class FileStore {
  constructor({ dir, secret, siteUrl }) {
    this.dir = dir;
    this.secret = secret;
    this.siteUrl = siteUrl;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  #path(name) {
    return path.join(this.dir, name.slice(0, 2), name);
  }

  #sign(name, exp) {
    return crypto.createHmac("sha256", this.secret).update(`file:${name}:${exp}`).digest("base64url");
  }

  async upload(file) {
    const bytes = Buffer.from(await file.arrayBuffer());
    const name = crypto.randomBytes(24).toString("hex");
    const p = this.#path(name);
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
    fs.writeFileSync(p, bytes, { mode: 0o600 });
    return { file_uri: `private://${name}` };
  }

  signedUrl(fileUri, expiresIn = 300) {
    const m = URI_RE.exec(String(fileUri || ""));
    if (!m) throw new Error("Unknown file");
    const exp = Math.floor(Date.now() / 1000) + Math.max(10, Math.min(Number(expiresIn) || 300, 3600));
    return { signed_url: `${this.siteUrl}/api/files/${m[1]}?exp=${exp}&sig=${this.#sign(m[1], exp)}` };
  }

  /** The file for a signed link, or null if the link is wrong or has run out. */
  open(name, exp, sig) {
    if (!/^[a-f0-9]{48}$/.test(name) || !/^\d{1,12}$/.test(String(exp || ""))) return null;
    if (Number(exp) < Date.now() / 1000) return null;
    const want = Buffer.from(this.#sign(name, exp));
    const got = Buffer.from(String(sig || ""));
    if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
    const p = this.#path(name);
    return fs.existsSync(p) ? p : null;
  }

  remove(fileUri) {
    const m = URI_RE.exec(String(fileUri || ""));
    if (m) fs.rmSync(this.#path(m[1]), { force: true });
  }
}
