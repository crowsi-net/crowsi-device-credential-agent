#[test]
fn recovery_approval_key_rejects_parent_file_link_and_digest_drift() {
    use std::{fs, os::unix::fs::PermissionsExt, os::unix::fs::symlink};

    for case in 0..6 {
        let fixture = Fixture::new();
        let key = fixture.recovery_key_path();
        match case {
            0 => fs::set_permissions(
                key.parent().expect("parent"),
                fs::Permissions::from_mode(0o750),
            )
            .expect("parent mode"),
            1 => fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).expect("key mode"),
            2 => fs::hard_link(&key, key.with_extension("link")).expect("hard link"),
            3 => {
                let target = key.with_extension("target");
                fs::copy(&key, &target).expect("copy key");
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                    .expect("target mode");
                fs::remove_file(&key).expect("remove key");
                symlink(&target, &key).expect("key symlink");
            }
            4 => {
                let parent = key.parent().expect("parent");
                let target = parent.with_extension("target");
                fs::rename(parent, &target).expect("move parent");
                symlink(&target, parent).expect("parent symlink");
            }
            _ => fs::write(&key, b"substituted").expect("substitute key"),
        }
        assert!(matches!(
            fixture.try_core(),
            Err(AgentError::PathInvalid | AgentError::ConfigInvalid)
        ));
    }
}
