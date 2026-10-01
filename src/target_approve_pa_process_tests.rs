use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use crate::target_approve_process_identity::ProcessIdentity;

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn non_reader_cannot_hold_a_large_stdin_write_past_the_deadline() {
    let (root, identity) = helper("#!/bin/sh\n/bin/sleep 30\n");
    let started = Instant::now();
    let result = crate::target_approve_pa_process::invoke_test(
        &identity,
        Duration::from_millis(150),
        &vec![b'x'; 2 * 1024 * 1024],
    );
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(identity);
    fs::remove_dir_all(root).expect("remove helper root");
}

#[test]
fn stdout_holding_grandchild_is_killed_and_joined() {
    let script = "#!/bin/sh\nIFS= read -r input || :\n(/bin/sleep 30) &\nprintf '{}'\nexit 0\n";
    let (root, identity) = helper(script);
    let started = Instant::now();
    let result =
        crate::target_approve_pa_process::invoke_test(&identity, Duration::from_millis(500), b"{}");
    assert_eq!(result.expect("bounded response"), b"{}");
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(identity);
    fs::remove_dir_all(root).expect("remove helper root");
}

fn helper(script: &str) -> (PathBuf, ProcessIdentity) {
    let suffix = NEXT.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("crowsi-target-pa-{}-{suffix}", std::process::id()));
    fs::create_dir(&root).expect("create helper root");
    let path = root.join("pa-helper");
    fs::write(&path, script).expect("write helper");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("helper mode");
    let digest = format!("sha256:{:x}", Sha256::digest(script.as_bytes()));
    let identity =
        ProcessIdentity::open(path.to_str().expect("path"), &digest).expect("pinned helper");
    (root, identity)
}
