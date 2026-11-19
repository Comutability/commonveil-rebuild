// Stands in for src/lib/api.js in tests (see apiStubLoader.mjs): calls go to whatever the test
// sets as globalThis.__commonveilCallFn.
export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export async function callFn(fn, body) {
  return globalThis.__commonveilCallFn(fn, body);
}
