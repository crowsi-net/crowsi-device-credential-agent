use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, ManagementRequestV2, decode_endpoint_management_envelope_strict,
};
use crowsi_device_credential_agent::{AgentError, test_support::AuthorityTransport};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct FakeTransport {
    binding: String,
    response: Arc<Mutex<Vec<u8>>>,
    lookup_response: Arc<Mutex<Vec<u8>>>,
    finalize_response: Arc<Mutex<Vec<u8>>>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    source_approve_requests: Arc<Mutex<Vec<Vec<u8>>>>,
    reservation_requests: Arc<Mutex<Vec<Vec<u8>>>>,
    finalize_requests: Arc<Mutex<Vec<Vec<u8>>>>,
    execution_cancel_requests: Arc<Mutex<Vec<Vec<u8>>>>,
    cancel_finalize_requests: Arc<Mutex<Vec<Vec<u8>>>>,
    cleanup_complete_requests: Arc<Mutex<Vec<Vec<u8>>>>,
    fail_source_approve_once: Arc<Mutex<bool>>,
    fail_finalize_once: Arc<Mutex<bool>>,
    fail_reservation_once: Arc<Mutex<bool>>,
    fail_execution_cancel_once: Arc<Mutex<bool>>,
    fail_cancel_finalize_once: Arc<Mutex<bool>>,
    fail_cleanup_complete_once: Arc<Mutex<bool>>,
}

impl FakeTransport {
    pub fn new(binding: String) -> Self {
        Self {
            binding,
            response: Arc::new(Mutex::new(vec![])),
            lookup_response: Arc::new(Mutex::new(vec![])),
            finalize_response: Arc::new(Mutex::new(vec![])),
            requests: Arc::new(Mutex::new(vec![])),
            source_approve_requests: Arc::new(Mutex::new(vec![])),
            reservation_requests: Arc::new(Mutex::new(vec![])),
            finalize_requests: Arc::new(Mutex::new(vec![])),
            execution_cancel_requests: Arc::new(Mutex::new(vec![])),
            cancel_finalize_requests: Arc::new(Mutex::new(vec![])),
            cleanup_complete_requests: Arc::new(Mutex::new(vec![])),
            fail_source_approve_once: Arc::new(Mutex::new(false)),
            fail_finalize_once: Arc::new(Mutex::new(false)),
            fail_reservation_once: Arc::new(Mutex::new(false)),
            fail_execution_cancel_once: Arc::new(Mutex::new(false)),
            fail_cancel_finalize_once: Arc::new(Mutex::new(false)),
            fail_cleanup_complete_once: Arc::new(Mutex::new(false)),
        }
    }
}

impl AuthorityTransport for FakeTransport {
    fn route_binding_sha256(&self) -> Result<String, AgentError> {
        Ok(self.binding.clone())
    }
    fn exchange(&self, route: &str, request: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
        self.requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(request.to_vec());
        if route == "revocation-finalize" {
            self.finalize_requests
                .lock()
                .map_err(|_| AgentError::AuthorityUnavailable)?
                .push(request.to_vec());
            if std::mem::take(
                &mut *self
                    .fail_finalize_once
                    .lock()
                    .map_err(|_| AgentError::AuthorityUnavailable)?,
            ) {
                return Err(AgentError::AuthorityUnavailable);
            }
        }
        if route == "source-approve" {
            self.source_approve_requests
                .lock()
                .map_err(|_| AgentError::AuthorityUnavailable)?
                .push(request.to_vec());
            if std::mem::take(
                &mut *self
                    .fail_source_approve_once
                    .lock()
                    .map_err(|_| AgentError::AuthorityUnavailable)?,
            ) {
                return Err(AgentError::AuthorityUnavailable);
            }
        }
        if route == "revocation-execution-reserve" {
            self.reservation_requests
                .lock()
                .map_err(|_| AgentError::AuthorityUnavailable)?
                .push(request.to_vec());
            if self.take_failure(&self.fail_reservation_once)? {
                return Err(AgentError::AuthorityUnavailable);
            }
            let pre_final = self
                .response
                .lock()
                .map_err(|_| AgentError::AuthorityUnavailable)?
                .clone();
            return crate::management_support_reservation::response(request, &pre_final, now);
        }
        if route == "revocation-execution-cancel" {
            return self.execution_cancel(request, now);
        }
        if route == "revocation-execution-cancel-finalize" {
            return self.cancel_finalize(request, now);
        }
        if route == "revocation-execution-cancel-cleanup-complete" {
            return self.cleanup_complete(request, now);
        }
        let response = if route == "lookup-prepared" {
            &self.lookup_response
        } else if route == "revocation-finalize" {
            &self.finalize_response
        } else {
            &self.response
        };
        Ok(response
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .clone())
    }
}

include!("management_support_transport_cancellation.rs");
include!("management_support_transport_access.rs");

pub fn assert_passive_requests(requests: Vec<Vec<u8>>, expected: &ManagementRequestV2) {
    assert_eq!(requests.len(), 2);
    for wire in requests {
        let envelope = decode_endpoint_management_envelope_strict(&wire).expect("envelope");
        assert_eq!(&envelope.browser_request, expected);
        assert!(matches!(
            envelope.evidence,
            EndpointManagementEvidenceV2::Passive { .. }
        ));
    }
}
