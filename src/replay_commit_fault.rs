use crate::AgentError;

#[cfg(test)]
thread_local! { static FAIL_AFTER: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
pub(super) fn fail_after(point: u8) {
    FAIL_AFTER.with(|value| value.set(point));
}

#[cfg(test)]
pub(super) fn cut(point: u8) -> Result<(), AgentError> {
    FAIL_AFTER.with(|value| {
        if value.get() == point {
            value.set(0);
            Err(AgentError::AuthorityUnavailable)
        } else {
            Ok(())
        }
    })
}

#[cfg(not(test))]
pub(super) const fn cut(_: u8) -> Result<(), AgentError> {
    Ok(())
}
