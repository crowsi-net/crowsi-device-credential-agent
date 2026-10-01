#![forbid(unsafe_code)]

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("test-support is forbidden in release builds");

include!("lib_actor_options_modules.rs");
include!("lib_cancel_modules.rs");
include!("lib_independent_approve_modules.rs");
include!("lib_reconcile_modules.rs");
include!("lib_retired_request_modules.rs");
include!("lib_source_approve_revocation_modules.rs");
include!("lib_target_approve_modules.rs");
mod cli;
mod config;
mod config_mappings;
mod config_route;
mod config_validation;
mod config_validation_aliases;
mod config_validation_roles;
mod config_validation_routes;
mod config_verify;
mod core;
mod core_active;
mod core_envelope;
mod core_identity;
mod core_projection;
#[cfg(feature = "test-support")]
mod core_test_support;
mod core_validation;
mod crypto;
mod error;
mod fresh_uv_options;
mod identity_client;
mod identity_client_current_request;
mod identity_client_current_response;
mod identity_client_finish;
mod identity_client_fresh;
mod identity_locator;
mod identity_locator_io;
#[cfg(test)]
mod identity_locator_tests;
mod identity_locator_validation;
mod identity_provider;
mod identity_verify;
mod management_state;
#[cfg(test)]
mod management_state_tests;
mod operation_artifact_cleanup;
mod prepared_operation;
mod prepared_operation_revocation;
mod prepared_operation_snapshot;
#[cfg(test)]
mod prepared_operation_test_support;
#[cfg(test)]
mod prepared_operation_tests;
mod process_identity;
mod random_id;
mod remote_transport;
mod replay;
mod replay_ancestor;
mod replay_commit;
mod replay_commit_fault;
#[cfg(test)]
mod replay_crash_tests;
#[cfg(test)]
mod replay_execution_lock_tests;
mod replay_file;
mod replay_file_mutation;
mod replay_initialize;
mod replay_layout;
mod replay_metadata;
mod replay_namespace;
mod replay_namespace_limits;
#[cfg(test)]
mod replay_namespace_tests;
#[cfg(test)]
mod replay_path_tests;
mod replay_record;
mod replay_recover;
mod replay_recover_prune;
mod replay_recover_transaction;
mod replay_recover_transaction_finish;
mod replay_recover_transaction_io;
mod replay_recover_validation;
mod replay_scan;
mod replay_scan_integrity;
mod replay_scan_names;
mod replay_scan_validate;
mod replay_security;
#[cfg(test)]
mod replay_security_tests;
#[cfg(test)]
mod replay_tamper_tests;
#[cfg(test)]
mod replay_test_support;
#[cfg(test)]
mod replay_tests;
mod session_sender;
mod source_approve;
mod source_approve_prepare;
mod source_approve_response;
mod source_approve_response_verify;
mod source_approve_state;
mod source_approve_state_phase;
mod source_approve_state_reserve;
mod source_approve_state_response;
mod source_approve_state_transition;
mod source_approve_state_types;
mod source_approve_state_validation;
mod source_approve_state_wire;
mod source_approve_verify;
mod source_options;
mod source_options_prepare;
mod source_options_response;
mod source_options_scope;
mod source_options_scope_validation;
mod source_options_state;
mod source_options_state_reserve;
mod source_options_state_response;
mod source_options_state_transition;
mod source_options_state_types;
mod source_options_state_validation;
mod source_options_verify;
mod transport;

pub use cli::run_cli;
pub use config::{
    AgentConfigDocument, ManagementProjectionTrust, RemoteAuthorityRoute, RootTrustDocument,
    VerifiedConfig, authority_route_binding_sha256, verify_config,
};
pub use crypto::canonical_signed_document;
pub use error::AgentError;

#[cfg(feature = "test-support")]
pub mod test_support {
    include!("lib_test_support.rs");
}
