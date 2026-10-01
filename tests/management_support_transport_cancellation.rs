impl FakeTransport {
    pub fn execution_cancel_requests(&self) -> Vec<Vec<u8>> {
        self.execution_cancel_requests
            .lock()
            .expect("execution cancel requests")
            .clone()
    }

    pub fn cancel_finalize_requests(&self) -> Vec<Vec<u8>> {
        self.cancel_finalize_requests
            .lock()
            .expect("cancel finalize requests")
            .clone()
    }

    pub fn cleanup_complete_requests(&self) -> Vec<Vec<u8>> {
        self.cleanup_complete_requests
            .lock()
            .expect("cleanup complete requests")
            .clone()
    }

    pub fn fail_reservation_once(&self) {
        *self.fail_reservation_once.lock().expect("reserve failure") = true;
    }

    pub fn fail_execution_cancel_once(&self) {
        *self
            .fail_execution_cancel_once
            .lock()
            .expect("execution cancel failure") = true;
    }

    pub fn fail_cancel_finalize_once(&self) {
        *self
            .fail_cancel_finalize_once
            .lock()
            .expect("cancel finalize failure") = true;
    }
    pub fn fail_cleanup_complete_once(&self) {
        *self
            .fail_cleanup_complete_once
            .lock()
            .expect("cleanup complete failure") = true;
    }

    fn execution_cancel(&self, request: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
        self.execution_cancel_requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(request.to_vec());
        if self.take_failure(&self.fail_execution_cancel_once)? {
            return Err(AgentError::AuthorityUnavailable);
        }
        let projection = self
            .response
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .clone();
        crate::management_support_cancellation::response(request, &projection, now)
    }

    fn cancel_finalize(&self, request: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
        self.cancel_finalize_requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(request.to_vec());
        if self.take_failure(&self.fail_cancel_finalize_once)? {
            return Err(AgentError::AuthorityUnavailable);
        }
        crate::management_support_cancellation_cleanup::response(request, now)
    }

    fn cleanup_complete(&self, request: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
        self.cleanup_complete_requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(request.to_vec());
        let response =
            crate::management_support_cancellation_cleanup_complete::response(request, now)?;
        if self.take_failure(&self.fail_cleanup_complete_once)? {
            return Err(AgentError::AuthorityUnavailable);
        }
        Ok(response)
    }

    fn take_failure(&self, value: &Mutex<bool>) -> Result<bool, AgentError> {
        Ok(std::mem::take(
            &mut *value.lock().map_err(|_| AgentError::AuthorityUnavailable)?,
        ))
    }
}
