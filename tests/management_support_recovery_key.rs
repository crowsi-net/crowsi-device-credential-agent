fn install_recovery_key(root: &std::path::Path, config: &mut Value) {
    use sha2::{Digest, Sha256};

    let directory = root.join("recovery-approval");
    fs::create_dir(&directory).expect("recovery directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("recovery directory mode");
    let document = json!({
        "schema":"crowsi://device-credential-agent/recovery-approval-key/v1",
        "key_id":"recovery-approval-key",
        "private_key_hex":hex::encode(SigningKey::from_bytes(&[8; 32]).to_bytes()),
    });
    let wire = serde_json::to_vec(&document).expect("recovery key");
    let path = directory.join("key.json");
    fs::write(&path, &wire).expect("recovery key write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("recovery key mode");
    config["recovery_approval_private_key_sha256"] =
        format!("sha256:{}", hex::encode(Sha256::digest(&wire))).into();
}
