impl FakeIdentity {
    pub fn cancel_pending_requests(&self) -> Vec<AuthorityRequestV1> {
        self.cancel_pending_requests
            .lock()
            .expect("cancel pending requests")
            .clone()
    }

    pub fn cleanup_ack_requests(&self) -> Vec<AuthorityRequestV1> {
        self.cleanup_ack_requests
            .lock()
            .expect("cleanup ack requests")
            .clone()
    }

    pub fn fail_cancel_pending_once(&self) {
        *self
            .fail_cancel_pending_once
            .lock()
            .expect("cancel pending failure") = true;
    }

    pub fn fail_cleanup_ack_once(&self) {
        *self
            .fail_cleanup_ack_once
            .lock()
            .expect("cleanup ack failure") = true;
    }
}
