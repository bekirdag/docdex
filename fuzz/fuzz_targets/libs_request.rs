#![no_main]

use docdexd::api::v1::libs::LibsRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = serde_json::from_slice::<LibsRequest>(data) {
        let _ = req.repo_id.as_deref();
        let _ = req.sources_path.as_deref();
    }
});
