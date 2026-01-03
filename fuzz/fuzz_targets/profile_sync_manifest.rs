#![no_main]

use docdexd::api::v1::profile::ProfileSyncManifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = serde_json::from_slice::<ProfileSyncManifest>(data) {
        let _ = manifest.schema_version;
        let _ = manifest.embedding_dim;
        let _ = manifest.agents.len();
        let _ = manifest.preferences.len();
    }
});
