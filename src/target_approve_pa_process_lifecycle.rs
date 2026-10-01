use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use std::{
    process::Child,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use crate::AgentError;

pub(super) struct Workers {
    pub(super) writer: JoinHandle<()>,
    pub(super) reader: JoinHandle<()>,
}

pub(super) fn abort(child: &mut Child, workers: Workers) -> AgentError {
    terminate(child);
    join(workers)
        .err()
        .unwrap_or(AgentError::AuthorityUnavailable)
}

pub(super) fn join(workers: Workers) -> Result<(), AgentError> {
    let writer = workers.writer.join();
    let reader = workers.reader.join();
    (writer.is_ok() && reader.is_ok())
        .then_some(())
        .ok_or(AgentError::AuthorityUnavailable)
}

pub(super) fn left(started: Instant, timeout: Duration) -> Duration {
    timeout.saturating_sub(started.elapsed())
}

pub(super) fn kill_group(child: &Child) {
    if let Ok(id) = i32::try_from(child.id()) {
        let _ = killpg(Pid::from_raw(id), Signal::SIGKILL);
    }
}

pub(super) fn terminate(child: &mut Child) {
    kill_group(child);
    let _ = child.wait();
}
