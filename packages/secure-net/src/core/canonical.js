// Canonical JSON for everything Secure Net signs (CVP-002).
//
// The same value always gives the same bytes, on every platform: object keys sorted by UTF-16
// code unit (as RFC 8785 does), no whitespace, and only values that encode one way. Numbers must
// be safe integers: fractions and exponents have more than one spelling, so they're refused
// rather than normalised. Encode a fraction as two integers, or as a string.

export class CanonicalError extends Error {
  constructor(message) {
    super(message);
    this.name = "CanonicalError";
    this.code = "NOT_CANONICAL";
  }
}

function encode(value, path, seen) {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      if (/[\uD800-\uDFFF]/.test(value.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, ""))) {
        throw new CanonicalError(`${path} has a broken character (a lone surrogate)`);
      }
      return JSON.stringify(value);
    case "number":
      if (!Number.isSafeInteger(value)) throw new CanonicalError(`${path} isn't a whole number in the safe range`);
      return Object.is(value, -0) ? "0" : String(value);
    case "object": {
      if (seen.has(value)) throw new CanonicalError(`${path} refers to itself`);
      seen.add(value);
      let out;
      if (Array.isArray(value)) {
        out = `[${value.map((v, i) => encode(v, `${path}[${i}]`, seen)).join(",")}]`;
      } else {
        const proto = Object.getPrototypeOf(value);
        if (proto !== Object.prototype && proto !== null) throw new CanonicalError(`${path} isn't a plain object`);
        const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
        out = `{${keys.map((k) => `${JSON.stringify(k)}:${encode(value[k], `${path}.${k}`, seen)}`).join(",")}}`;
      }
      seen.delete(value);
      return out;
    }
    default:
      throw new CanonicalError(`${path} can't be signed (${typeof value})`);
  }
}

/** The canonical text of a value. Throws CanonicalError for anything with more than one encoding. */
export const canonicalJson = (value) => encode(value, "$", new Set());

/** The canonical bytes of a value. */
export const canonicalBytes = (value) => new TextEncoder().encode(canonicalJson(value));
