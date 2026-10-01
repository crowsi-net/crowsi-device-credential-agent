impl Fixture {
    pub fn fail_reservation_once(&self) {
        self.transport.fail_reservation_once();
    }

    pub fn fail_execution_cancel_once(&self) {
        self.transport.fail_execution_cancel_once();
    }

    pub fn fail_cancel_finalize_once(&self) {
        self.transport.fail_cancel_finalize_once();
    }

    pub fn fail_cleanup_complete_once(&self) {
        self.transport.fail_cleanup_complete_once();
    }

    pub fn execution_cancel_requests(&self) -> Vec<Vec<u8>> {
        self.transport.execution_cancel_requests()
    }

    pub fn cancel_finalize_requests(&self) -> Vec<Vec<u8>> {
        self.transport.cancel_finalize_requests()
    }

    pub fn cleanup_complete_requests(&self) -> Vec<Vec<u8>> {
        self.transport.cleanup_complete_requests()
    }

    pub fn fail_cancel_pending_once(&self) {
        self.identity.fail_cancel_pending_once();
    }

    pub fn fail_cleanup_ack_once(&self) {
        self.identity.fail_cleanup_ack_once();
    }

    pub fn cancel_pending_requests(
        &self,
    ) -> Vec<ihat_identity_assertion_contracts::AuthorityRequestV1> {
        self.identity.cancel_pending_requests()
    }

    pub fn cleanup_ack_requests(
        &self,
    ) -> Vec<ihat_identity_assertion_contracts::AuthorityRequestV1> {
        self.identity.cleanup_ack_requests()
    }
}
