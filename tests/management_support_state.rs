use crowsi_device_credential_agent::test_support::{initialize_locator, initialize_state};
use serde_json::Value;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

use crate::management_support::{NOW, SESSION};

pub fn initialize(root: &Path, config: &Value, trust: &[u8]) {
    let config = serde_json::to_vec(config).expect("initial config");
    let uid = fs::metadata(root).expect("uid").uid();
    initialize_state(&config, trust, NOW, uid).expect("initialize state");
    initialize_locator(&config, trust, SESSION, NOW, uid).expect("initialize locator");
}
