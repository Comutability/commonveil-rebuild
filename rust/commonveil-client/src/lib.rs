//! Commonveil's client core, compiled to WebAssembly for the browser app.
//!
//! Today it is Secure Net's JSON API as one entry point, built from the same pinned Secure Net
//! commit as the self-hosted server, so every part of Commonveil runs the same Rust. Commonveil's
//! own client logic (keyrings, sessions, device sync, backup, moves) moves in here from
//! JavaScript stage by stage; see the implementation plan's Stage 0.
//!
//! Device signing and box keys, and the passcode lock's key, are not handled here in a browser:
//! WebAssembly memory can't hide a key from page script, so those stay non-extractable WebCrypto
//! keys, as Secure Net's `cv::device` and `cv::lock` notes say.
//!
//! Build (CI does this; see the `wasm` job in .github/workflows/test.yml):
//!   cargo build --profile wasm --target wasm32-unknown-unknown -p commonveil-client
//!   wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/wasm/commonveil_client.wasm
use wasm_bindgen::prelude::*;

/// Run one request: `{ "op": ..., ... }` in, `{ "ok": ... }` or `{ "error": { code, message } }` out,
/// exactly as `secure_net_core::api` describes.
#[wasm_bindgen]
pub fn call(request: &str) -> String {
    secure_net_core::api::call_text(request)
}

/// The Secure Net release this build carries.
#[wasm_bindgen(js_name = secureNetVersion)]
pub fn secure_net_version() -> String {
    secure_net_core::wire::features::SECURE_NET_VERSION.to_string()
}

/// This crate's version, the Commonveil release it was built for.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn ok(request: Value) -> Value {
        let reply: Value = serde_json::from_str(&call(&request.to_string())).unwrap();
        assert!(reply.get("error").is_none(), "{request} failed: {reply}");
        reply["ok"].clone()
    }

    #[test]
    fn answers_as_secure_net_does() {
        assert_eq!(ok(json!({ "op": "canonical", "value": { "b": 1, "a": 2 } })), json!("{\"a\":2,\"b\":1}"));
        let text = ok(json!({ "op": "cv.canonical", "context": "test/v1", "fields": ["a", "b|c"] }));
        assert_eq!(text, json!("commonveil/test/v1\n2\na\nb|c"));
    }

    #[test]
    fn bad_requests_are_errors_not_panics() {
        let reply: Value = serde_json::from_str(&call("not json")).unwrap();
        assert_eq!(reply["error"]["code"], "BAD_INPUT");
        let reply: Value = serde_json::from_str(&call(&json!({ "op": "cv.noSuchThing" }).to_string())).unwrap();
        assert_eq!(reply["error"]["code"], "BAD_INPUT");
    }

    #[test]
    fn versions() {
        assert_eq!(secure_net_version(), secure_net_core::wire::features::SECURE_NET_VERSION);
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
