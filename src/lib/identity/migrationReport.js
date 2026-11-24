// Experimental client-side encrypted reconciliation report, not an account importer.
// Secure Net remains independent of Commonveil and of any identity issuer.
// This helper requires a PREVIOUSLY AUTHORISED non-extractable AES-256-GCM
// device key. It does not create, wrap, export or enrol recipient keys.
// The owner must independently authenticate the receiving device.
const MAGIC = Uint8Array.from([0x43, 0x56, 0x52, 0x50, 0x54, 0x01]); // CVRPT\x01
const MAX_CIPHERTEXT = 64 * 1024;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = MAGIC.length + NONCE_BYTES;

export class MigrationReportError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "MigrationReportError";
    this.code = code;
  }
}

function requireContext(context) {
  if (!context || typeof context !== "object") {
    throw new MigrationReportError("BAD_CONTEXT", "A recipient and stage are required.");
  }
  const { actorId, stageId, destination, ciphertextRoot, recipientDeviceId } = context;
  const isB64u = (v, min, max) => typeof v === "string" &&
    v.length >= min && v.length <= max && /^[A-Za-z0-9_-]+$/.test(v);
  if (!isB64u(actorId, 16, 90) || !isB64u(stageId, 20, 90) ||
      !isB64u(ciphertextRoot, 43, 43) || !isB64u(recipientDeviceId, 12, 90) ||
      typeof destination !== "string" || destination.length > 253 ||
      destination === "localhost" || destination.endsWith(".localhost") ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(destination) ||
      /^(?:[0-9]+\\.){3}[0-9]+$/.test(destination)) {
    throw new MigrationReportError("BAD_CONTEXT", "Invalid actor, stage, recipient or destination binding.");
  }
  return new TextEncoder().encode(
    "secure-net/transfer.report/v1\n" +
    JSON.stringify([actorId, stageId, destination, ciphertextRoot, recipientDeviceId])
  );
}

function requireDeviceKey(key, operation) {
  if (key?.type !== "secret" || key.algorithm?.name !== "AES-GCM" ||
      key.algorithm?.length !== 256 || key.extractable !== false ||
      !key.usages?.includes(operation)) {
    throw new MigrationReportError(
      "KEY_REQUIRED",
      "Use an already authorised, non-extractable AES-256-GCM device key."
    );
  }
}

const bytesOf = (bytes) => {
  if (bytes instanceof Uint8Array) return bytes;
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
  throw new MigrationReportError("BAD_REPORT", "The encrypted report must be raw bytes.");
};

export async function encryptMigrationReport({ report, recipientKey, context }) {
  requireDeviceKey(recipientKey, "encrypt");
  const additionalData = requireContext(context);
  if (!report || typeof report !== "object" || Array.isArray(report) || report.version !== 1) {
    throw new MigrationReportError("BAD_REPORT", "Expected a version 1 private reconciliation report.");
  }
  let plaintext;
  try {
    plaintext = new TextEncoder().encode(JSON.stringify(report));
    if (plaintext.length < 1 || plaintext.length + HEADER_BYTES + TAG_BYTES > MAX_CIPHERTEXT) {
      throw new MigrationReportError("REPORT_SIZE_LIMIT", "Report exceeds the 64 KiB staging limit.");
    }
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const sealed = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
      recipientKey, plaintext
    ));
    const output = new Uint8Array(HEADER_BYTES + sealed.length);
    output.set(MAGIC);
    output.set(nonce, MAGIC.length);
    output.set(sealed, HEADER_BYTES);
    if (output.length < 48) {
      throw new MigrationReportError("REPORT_SIZE_LIMIT", "Encrypted report is unexpectedly small.");
    }
    return output;
  } finally {
    plaintext?.fill(0);
  }
}

export async function decryptMigrationReport({ ciphertext, recipientKey, context }) {
  requireDeviceKey(recipientKey, "decrypt");
  const additionalData = requireContext(context);
  const bytes = bytesOf(ciphertext);
  if (bytes.length < 48 || bytes.length > MAX_CIPHERTEXT ||
      !MAGIC.every((value, index) => bytes[index] === value)) {
    throw new MigrationReportError("BAD_REPORT", "Unsupported or oversized encrypted report.");
  }
  const nonce = bytes.subarray(MAGIC.length, HEADER_BYTES);
  const sealed = bytes.subarray(HEADER_BYTES);
  let plaintext;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
      recipientKey, sealed
    ));
    const report = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
    if (!report || Array.isArray(report) || report.version !== 1) {
      throw new Error("Wrong report version");
    }
    return report;
  } catch {
    throw new MigrationReportError("AUTH_FAILED", "The report could not be authenticated for this device and transfer.");
  } finally {
    plaintext?.fill(0);
  }
}
