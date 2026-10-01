use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

use crate::{
    AgentError,
    target_approve_pa_process_lifecycle::{Workers, abort, join, kill_group, left, terminate},
    target_approve_process_identity::ProcessIdentity,
};

pub(super) fn invoke(
    executable: &ProcessIdentity,
    config_path: &str,
    config_digest: &str,
    timeout: Duration,
    input: &[u8],
) -> Result<Vec<u8>, AgentError> {
    if input.is_empty()
        || input.len() > crowsi_windows_operation_contracts::MAX_OPERATION_AUTHORIZE_ONCE_BYTES
    {
        return Err(AgentError::RequestInvalid);
    }
    invoke_inner(executable, config_path, config_digest, timeout, input)
}

#[cfg(test)]
pub(super) fn invoke_test(
    executable: &ProcessIdentity,
    timeout: Duration,
    input: &[u8],
) -> Result<Vec<u8>, AgentError> {
    invoke_inner(
        executable,
        "/test/operation-authorize-once.json",
        &format!("sha256:{}", "0".repeat(64)),
        timeout,
        input,
    )
}

fn invoke_inner(
    executable: &ProcessIdentity,
    config_path: &str,
    config_digest: &str,
    timeout: Duration,
    input: &[u8],
) -> Result<Vec<u8>, AgentError> {
    let started = Instant::now();
    let mut child = spawn(executable, config_path, config_digest)?;
    let Some(mut stdin) = child.stdin.take() else {
        terminate(&mut child);
        return Err(AgentError::AuthorityUnavailable);
    };
    let Some(stdout) = child.stdout.take() else {
        terminate(&mut child);
        return Err(AgentError::AuthorityUnavailable);
    };
    let (write_sender, write_receiver) = mpsc::sync_channel(1);
    let input = input.to_vec();
    let writer = thread::spawn(move || {
        let _ = write_sender.send(stdin.write_all(&input));
    });
    let (read_sender, read_receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let _ = read_sender.send(bounded(stdout));
    });
    let workers = Workers { writer, reader };
    match child.wait_timeout(left(started, timeout)) {
        Ok(Some(status)) if status.success() => (),
        Ok(Some(_)) | Ok(None) | Err(_) => return Err(abort(&mut child, workers)),
    }
    kill_group(&child);
    let written = match write_receiver.recv_timeout(left(started, timeout)) {
        Ok(result) => result,
        Err(_) => return Err(abort(&mut child, workers)),
    };
    if written.is_err() {
        return Err(abort(&mut child, workers));
    }
    let output = match read_receiver.recv_timeout(left(started, timeout)) {
        Ok(result) => result,
        Err(_) => return Err(abort(&mut child, workers)),
    };
    let output = match output {
        Ok(output) => output,
        Err(error) => {
            terminate(&mut child);
            join(workers)?;
            return Err(error);
        }
    };
    join(workers)?;
    Ok(output)
}

fn spawn(
    executable: &ProcessIdentity,
    config_path: &str,
    config_digest: &str,
) -> Result<Child, AgentError> {
    Command::new(executable.path()?)
        .arg("operation-authorize-once")
        .arg("--config")
        .arg(config_path)
        .arg("--config-sha256")
        .arg(config_digest)
        .env_clear()
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| AgentError::AuthorityUnavailable)
}

fn bounded(mut output: impl Read) -> Result<Vec<u8>, AgentError> {
    let maximum = crate::source_options_state::MAXIMUM_PHASE_WIRE_BYTES;
    let mut wire = Vec::new();
    output
        .by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut wire)
        .map_err(|_| AgentError::AuthorityUnavailable)?;
    (!wire.is_empty() && wire.len() <= maximum)
        .then_some(wire)
        .ok_or(AgentError::ResponseInvalid)
}
