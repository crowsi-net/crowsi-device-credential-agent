use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::{
    AgentError, canonical_signed_document, test_support::AgentCore,
};

use crate::management_support_config;
use crate::management_support_identity::{FakeIdentity, provider};
use crate::management_support_projection::projection;
use crate::management_support_transport::FakeTransport;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

pub const NOW: u64 = 1_900_000_000;
pub const SESSION: &str = "sref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub struct Fixture {
    root: PathBuf,
    config: Vec<u8>,
    trust: Vec<u8>,
    projection_key: SigningKey,
    transport: FakeTransport,
    identity: FakeIdentity,
    _isolation: MutexGuard<'static, ()>,
}

static FIXTURE_ISOLATION: Mutex<()> = Mutex::new(());

impl Fixture {
    pub fn new() -> Self {
        Self::with_config_change(|_| {})
    }
    pub fn with_config_change(change: impl FnOnce(&mut Value)) -> Self {
        let isolation = FIXTURE_ISOLATION
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/crowsi-v6-tests");
        fs::create_dir_all(&base).expect("test root");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("test root mode");
        let root = base.join(format!("crowsi-v6-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).expect("state");
        let state = root.join("state");
        let anchor = root.join("anchor");
        fs::create_dir(&state).expect("state directory");
        fs::create_dir(&anchor).expect("anchor directory");
        for path in [&root, &state, &anchor] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let config_key = SigningKey::from_bytes(&[1; 32]);
        let projection_key = SigningKey::from_bytes(&[2; 32]);
        let mut config = management_support_config::value(&root, &projection_key);
        install_recovery_key(&root, &mut config);
        let trust = json!({"schema":"crowsi://device-credential-agent/root-trust/v1",
            "configuration_key_id":"config-key",
            "configuration_public_key_hex":hex::encode(config_key.verifying_key().to_bytes())});
        sign_config(&mut config, &config_key);
        let trust_wire = serde_json::to_vec(&trust).expect("trust");
        crate::management_support_state::initialize(&root, &config, &trust_wire);
        change(&mut config);
        sign_config(&mut config, &config_key);
        let binding = config["authority_route"]["binding_sha256"]
            .as_str()
            .expect("binding")
            .into();
        Self {
            root,
            config: serde_json::to_vec(&config).expect("config"),
            trust: trust_wire,
            projection_key,
            transport: FakeTransport::new(binding),
            identity: provider(),
            _isolation: isolation,
        }
    }
    pub fn core(&self) -> AgentCore<FakeTransport, FakeIdentity> {
        self.try_core().expect("core")
    }
    pub fn try_core(&self) -> Result<AgentCore<FakeTransport, FakeIdentity>, AgentError> {
        AgentCore::from_documents(
            &self.config,
            &self.trust,
            self.transport.clone(),
            self.identity.clone(),
            NOW,
        )
    }
    pub fn respond(
        &self,
        request: &ManagementRequestV2,
        revision: u64,
        change: impl FnOnce(&mut ManagementProjectionV2),
    ) {
        let mut value = projection(request, revision);
        change(&mut value);
        value.signature = hex::encode(
            self.projection_key
                .sign(&canonical_management_projection(&value).expect("canonical"))
                .to_bytes(),
        );
        self.transport
            .respond(serde_json::to_vec(&value).expect("wire"));
    }
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.transport.requests()
    }
    pub fn begin_requests(&self) -> Vec<ihat_identity_assertion_contracts::AuthorityRequestV1> {
        self.identity.begin_requests()
    }
    pub fn finish_requests(&self) -> Vec<ihat_identity_assertion_contracts::AuthorityRequestV1> {
        self.identity.finish_requests()
    }
    pub fn current_requests(&self) -> Vec<ihat_identity_assertion_contracts::AuthorityRequestV1> {
        self.identity.current_requests()
    }
    pub fn fail_finish_once(&self) {
        self.identity.fail_finish_once();
    }
    pub fn fail_current_once(&self) {
        self.identity.fail_current_once();
    }
    pub fn recovery_key_path(&self) -> PathBuf {
        self.root.join("recovery-approval/key.json")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

include!("management_support_lookup.rs");
include!("management_support_cancellation_fixture.rs");
include!("management_support_guard.rs");
include!("management_support_recovery_key.rs");

fn sign_config(value: &mut Value, key: &SigningKey) {
    let payload =
        canonical_signed_document("CROWSI-DEVICE-CREDENTIAL-CONFIG-V6", value).expect("canonical");
    value["signature"] = hex::encode(key.sign(&payload).to_bytes()).into();
}
