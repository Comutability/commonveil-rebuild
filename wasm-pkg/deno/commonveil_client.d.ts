/* tslint:disable */
/* eslint-disable */

/**
 * Run one request: `{ "op": ..., ... }` in, `{ "ok": ... }` or `{ "error": { code, message } }` out,
 * exactly as `secure_net_core::api` describes.
 */
export function call(request: string): string;

/**
 * The Secure Net release this build carries.
 */
export function secureNetVersion(): string;

/**
 * This crate's version, the Commonveil release it was built for.
 */
export function version(): string;
