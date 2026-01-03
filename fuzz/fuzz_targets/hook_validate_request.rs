#![no_main]

use docdexd::api::v1::hooks::HookValidateRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = serde_json::from_slice::<HookValidateRequest>(data) {
        let _ = req.files.len();
    }
});
