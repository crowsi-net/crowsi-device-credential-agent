impl Fixture {
    pub fn leave_unlocked_guard_file(&self) {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.root.join("state/ledger.lock"))
            .expect("stale lock file");
    }
}
