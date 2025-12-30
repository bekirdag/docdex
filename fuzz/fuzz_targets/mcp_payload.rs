#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        if let Some(obj) = value.as_object() {
            let _ = obj.get("jsonrpc").and_then(|v| v.as_str());
            let _ = obj.get("method").and_then(|v| v.as_str());
            let _ = obj.get("id");
            let _ = obj.get("params");
        }
    }
});
