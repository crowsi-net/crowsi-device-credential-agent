use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use crowsi_device_credential_agent::{AgentError, test_support::IdentityEvidenceProvider};
use ihat_identity_assertion_contracts::AuthorityRequestV1;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct FakeIdentity {
    current: SignedAuthorityExchangeV1,
    begin_requests: Arc<Mutex<Vec<AuthorityRequestV1>>>,
    revocation_begin_requests: Arc<Mutex<Vec<AuthorityRequestV1>>>,
    revocation_final_requests: Arc<Mutex<Vec<AuthorityRequestV1>>>,
    finish_requests: Arc<Mutex<Vec<AuthorityRequestV1>>>,
    current_requests: Arc<Mutex<Vec<AuthorityRequestV1>>>,
    cancel_pending_requests: Arc<Mutex<Vec<AuthorityRequestV1>>>,
    cleanup_ack_requests: Arc<Mutex<Vec<AuthorityRequestV1>>>,
    cancel_pending_response: Arc<Mutex<Option<SignedAuthorityExchangeV1>>>,
    current_prepare_sequence: Arc<Mutex<u64>>,
    fail_revocation_begin_once: Arc<Mutex<bool>>,
    fail_revocation_final_once: Arc<Mutex<bool>>,
    substitute_revocation_final_once: Arc<Mutex<bool>>,
    fail_finish_once: Arc<Mutex<bool>>,
    fail_current_once: Arc<Mutex<bool>>,
    fail_cancel_pending_once: Arc<Mutex<bool>>,
    fail_cleanup_ack_once: Arc<Mutex<bool>>,
}

pub fn provider() -> FakeIdentity {
    FakeIdentity {
        current: crate::management_support_identity_current::exchange(),
        begin_requests: Arc::new(Mutex::new(Vec::new())),
        revocation_begin_requests: Arc::new(Mutex::new(Vec::new())),
        revocation_final_requests: Arc::new(Mutex::new(Vec::new())),
        finish_requests: Arc::new(Mutex::new(Vec::new())),
        current_requests: Arc::new(Mutex::new(Vec::new())),
        cancel_pending_requests: Arc::new(Mutex::new(Vec::new())),
        cleanup_ack_requests: Arc::new(Mutex::new(Vec::new())),
        cancel_pending_response: Arc::new(Mutex::new(None)),
        current_prepare_sequence: Arc::new(Mutex::new(0)),
        fail_revocation_begin_once: Arc::new(Mutex::new(false)),
        fail_revocation_final_once: Arc::new(Mutex::new(false)),
        substitute_revocation_final_once: Arc::new(Mutex::new(false)),
        fail_finish_once: Arc::new(Mutex::new(false)),
        fail_current_once: Arc::new(Mutex::new(false)),
        fail_cancel_pending_once: Arc::new(Mutex::new(false)),
        fail_cleanup_ack_once: Arc::new(Mutex::new(false)),
    }
}

impl FakeIdentity {
    pub fn begin_requests(&self) -> Vec<AuthorityRequestV1> {
        self.begin_requests.lock().expect("begin requests").clone()
    }
    pub fn finish_requests(&self) -> Vec<AuthorityRequestV1> {
        self.finish_requests
            .lock()
            .expect("finish requests")
            .clone()
    }
    pub fn revocation_begin_requests(&self) -> Vec<AuthorityRequestV1> {
        self.revocation_begin_requests
            .lock()
            .expect("revocation begin requests")
            .clone()
    }
    pub fn revocation_final_requests(&self) -> Vec<AuthorityRequestV1> {
        self.revocation_final_requests
            .lock()
            .expect("revocation final requests")
            .clone()
    }
    pub fn current_requests(&self) -> Vec<AuthorityRequestV1> {
        self.current_requests
            .lock()
            .expect("current requests")
            .clone()
    }
    pub fn fail_finish_once(&self) {
        *self.fail_finish_once.lock().expect("finish failure") = true;
    }
    pub fn fail_current_once(&self) {
        *self.fail_current_once.lock().expect("current failure") = true;
    }
    fn prepare_current(&self, now: u64) -> Result<AuthorityRequestV1, AgentError> {
        let mut sequence = self
            .current_prepare_sequence
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?;
        *sequence = sequence
            .checked_add(1)
            .ok_or(AgentError::AuthorityRollback)?;
        Ok(crate::management_support_identity_current_approval::prepare_at(now, *sequence))
    }
    pub fn fail_revocation_begin_once(&self) {
        *self
            .fail_revocation_begin_once
            .lock()
            .expect("revocation begin failure") = true;
    }
    pub fn substitute_revocation_final_once(&self) {
        *self
            .substitute_revocation_final_once
            .lock()
            .expect("revocation final substitution") = true;
    }
    pub fn fail_revocation_final_once(&self) {
        *self
            .fail_revocation_final_once
            .lock()
            .expect("revocation final failure") = true;
    }
    fn invoke_revocation_final(
        &self,
        prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
        begun: &SignedAuthorityExchangeV1,
        request: &AuthorityRequestV1,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.revocation_final_requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(request.clone());
        if std::mem::take(
            &mut *self
                .fail_revocation_final_once
                .lock()
                .map_err(|_| AgentError::IdentityUnavailable)?,
        ) {
            return Err(AgentError::IdentityUnavailable);
        }
        let substitute = std::mem::take(
            &mut *self
                .substitute_revocation_final_once
                .lock()
                .map_err(|_| AgentError::AuthorityUnavailable)?,
        );
        crate::management_support_identity_revocation::final_exchange(
            prepared, begun, request, now, substitute,
        )
    }
}

include!("management_support_identity_cancellation_state.rs");

include!("management_support_identity_provider.rs");
