import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/config-v6.schema.json"
ROOT_TRUST_PATH = "/etc/crowsi/device-credential-agent/root-trust.json"


def load_schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def valid_config():
    def digest(index):
        return "sha256:" + f"{index:064x}"

    def key(index):
        return f"{index:064x}"

    def route(name, authority, request_index, response_index):
        return {
            "schema": "crowsi://authority-transport/endpoint-route/v1",
            "binding_sha256": digest(request_index + 100),
            "address": f"{name}.example.test:443",
            "server_name": f"{name}.example.test",
            "audience": name,
            "device_id": "device-a",
            "endpoint_deployment_id": "endpoint-a",
            "authority_deployment_id": authority,
            "client_certificate_path": f"/etc/crowsi/{name}-client.der",
            "client_certificate_sha256": digest(request_index + 101),
            "client_private_key_path": f"/etc/crowsi/{name}-client.key",
            "client_private_key_sha256": digest(request_index + 102),
            "server_trust_anchor_path": f"/etc/crowsi/{name}-ca.der",
            "server_trust_anchor_sha256": digest(request_index + 103),
            "server_certificate_sha256": digest(request_index + 104),
            "request_key_id": f"{name}-request-key",
            "request_public_key_hex": key(request_index),
            "request_signing_key_path": f"/etc/crowsi/{name}-request.key",
            "request_signing_key_sha256": digest(request_index + 105),
            "response_key_id": f"{name}-response-key",
            "response_public_key_hex": key(response_index),
            "timeout_ms": 3000,
        }

    owner = "psa_owner_0000000000000001"
    return {
        "schema": "crowsi://device-credential-agent/config/v6",
        "deployment_role": "managed-device-endpoint",
        "endpoint_deployment_id": "endpoint-a",
        "configuration_generation": 1,
        "authority_route": route("credential-authority", "authority-a", 11, 12),
        "identity_authority_route": route("identity-authority", "identity-a", 13, 14),
        "pa_authorization_route": {
            "schema": "crowsi://device-credential-agent/pa-authorization-route/v1",
            "executable": "/usr/libexec/crowsi-pa-key-agent",
            "executable_sha256": digest(15),
            "config_path": "/etc/crowsi/pa-operation-authorize-once.json",
            "config_sha256": digest(16),
            "response_key_id": "pa-response-key",
            "response_public_key_hex": key(17),
            "timeout_ms": 3000,
        },
        "management_projection_trust": {
            "issuer": "crowsi-credential-authority",
            "audience": "endpoint-a",
            "service_id": "service-a",
            "pairwise_subject": "psu_pairwise-a",
            "opaque_account_ref": owner,
            "current_device_ref": "device-a",
            "minimum_subject_revocation_epoch": 1,
            "minimum_service_revocation_epoch": 1,
            "minimum_device_revocation_epoch": 1,
            "minimum_session_revocation_epoch": 1,
            "device_posture_state": "compliant",
            "minimum_device_posture_revision": 1,
            "device_proof_key_ref": "device-proof:device-a",
            "minimum_snapshot_revision": 1,
            "key_id": "management-key",
            "public_key_hex": key(18),
        },
        "authority_response_key_id": "authority-response-key",
        "authority_response_public_key_hex": key(19),
        "minimum_identity_config_generation": 1,
        "identity_finalization_authority_id": "identity-authority",
        "revocation_approval_authority_ref": "independent-authority-c",
        "identity_issuer": "ihat-authority",
        "identity_audience": "crowsi-management",
        "identity_key_id": "identity-key",
        "identity_public_key_hex": key(20),
        "current_status_key_id": "status-key",
        "current_status_public_key_hex": key(21),
        "user_verification_key_id": "uv-key",
        "user_verification_public_key_hex": key(22),
        "user_verification_credential_id": "webauthn-credential-a",
        "user_verification_account_binding_sha256": key(27),
        "session_sender_key_id": "session-sender-key",
        "session_sender_key_fingerprint": key(23),
        "session_sender_public_key_hex": key(23),
        "session_sender_private_key_path": "/etc/crowsi/session-sender.key",
        "session_sender_private_key_sha256": digest(24),
        "recovery_approval_key_id": "recovery-approval-key",
        "recovery_approval_key_fingerprint": key(28),
        "recovery_approval_public_key_hex": key(28),
        "recovery_approval_private_key_path": "/etc/crowsi/recovery-approval/key.json",
        "recovery_approval_private_key_sha256": digest(29),
        "revocation_execution_reservation_key_id": "revocation-reservation-key",
        "revocation_execution_reservation_public_key_hex": key(30),
        "minimum_reservation_config_generation": 1,
        "endpoint_state_directory": "/var/lib/crowsi/device-agent/state",
        "endpoint_anchor_directory": "/var/lib/crowsi/device-agent/anchor",
        "owner_mappings": [{
            "issuer": "ihat-authority", "service_id": "service-a",
            "pairwise_subject": "psu_pairwise-a", "opaque_owner_ref": owner,
        }],
        "device_proof_keys": [{
            "opaque_owner_ref": owner, "device_id": "device-a",
            "device_proof_key_ref": "device-proof:device-a",
            "public_key_hex": key(25), "custody": "hardware-nonexportable",
            "custody_executable": "/usr/libexec/crowsi-device-proof",
            "custody_executable_sha256": digest(26),
            "custody_credential_id": "credential-a",
            "custody_expected_revision": "rev1:" + "b" * 64,
        }],
        "issued_at_epoch_s": 1_900_000_000,
        "expires_at_epoch_s": 1_900_003_600,
        "configuration_key_id": "configuration-key",
        "signature": "aa" * 64,
    }
