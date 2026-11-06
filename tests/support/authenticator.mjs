// A software passkey (WebAuthn authenticator) for tests: P-256, "none" attestation, discoverable.
// It answers the JSON options the server makes, like @simplewebauthn/browser would hand back.
import crypto from "node:crypto";

const b64u = (b) => Buffer.from(b).toString("base64url");
const sha = (b) => crypto.createHash("sha256").update(b).digest();

// Just enough CBOR for an attestation object and a COSE key.
function cbor(v) {
  const head = (major, n) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  };
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)]);
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error("cbor: unsupported");
}

export class SoftPasskey {
  constructor({ origin, rpID, synced = false }) {
    this.origin = origin;
    this.rpID = rpID;
    this.synced = synced;
    this.credentials = new Map(); // id -> { key, userHandle, count }
  }

  #flags(extra) {
    // UP | UV, plus backup-eligible and backed-up when it's a synced passkey.
    return 0x01 | 0x04 | (this.synced ? 0x08 | 0x10 : 0) | extra;
  }

  /** Answer navigator.credentials.create() for registration options. */
  create(options) {
    const id = crypto.randomBytes(16);
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(id.length);
    const authData = Buffer.concat([sha(this.rpID), Buffer.from([this.#flags(0x40)]), Buffer.alloc(4), Buffer.alloc(16), idLen, id, cose]);
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin: this.origin, crossOrigin: false }));
    this.credentials.set(b64u(id), { key: privateKey, userHandle: options.user.id, count: 0 });
    return {
      id: b64u(id),
      rawId: b64u(id),
      type: "public-key",
      response: {
        clientDataJSON: b64u(clientData),
        attestationObject: b64u(cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]))),
        transports: ["internal"],
      },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }

  /** Answer navigator.credentials.get() for authentication options. */
  get(options) {
    const allowed = (options.allowCredentials || []).map((c) => c.id);
    const id = allowed.length ? allowed.find((x) => this.credentials.has(x)) : [...this.credentials.keys()][0];
    const cred = id && this.credentials.get(id);
    if (!cred) throw new Error("no matching passkey");
    cred.count += 1;
    const count = Buffer.alloc(4);
    count.writeUInt32BE(cred.count);
    const authData = Buffer.concat([sha(this.rpID), Buffer.from([this.#flags(0)]), count]);
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin: this.origin, crossOrigin: false }));
    const signature = crypto.sign("sha256", Buffer.concat([authData, sha(clientData)]), cred.key);
    return {
      id,
      rawId: id,
      type: "public-key",
      response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: cred.userHandle },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }
}
