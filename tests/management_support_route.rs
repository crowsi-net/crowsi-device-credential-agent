use crowsi_device_credential_agent::{RemoteAuthorityRoute, authority_route_binding_sha256};
use serde_json::json;

pub fn route() -> RemoteAuthorityRoute {
    let mut value: RemoteAuthorityRoute = serde_json::from_value(json!({
        "schema":"crowsi://authority-transport/endpoint-route/v1",
        "binding_sha256":format!("sha256:{}","0".repeat(64)),
        "address":"127.0.0.1:7443","server_name":"authority.test",
        "audience":"crowsi-authority","device_id":"device-a",
        "endpoint_deployment_id":"endpoint-a","authority_deployment_id":"authority-a",
        "client_certificate_path":"/etc/crowsi/client.der",
        "client_certificate_sha256":format!("sha256:{}","1".repeat(64)),
        "client_private_key_path":"/etc/crowsi/client.key",
        "client_private_key_sha256":format!("sha256:{}","2".repeat(64)),
        "server_trust_anchor_path":"/etc/crowsi/ca.der",
        "server_trust_anchor_sha256":format!("sha256:{}","3".repeat(64)),
        "server_certificate_sha256":format!("sha256:{}","4".repeat(64)),
        "request_key_id":"request-key","request_public_key_hex":"55".repeat(32),
        "request_signing_key_path":"/etc/crowsi/request.json",
        "request_signing_key_sha256":format!("sha256:{}","6".repeat(64)),
        "response_key_id":"response-key","response_public_key_hex":"77".repeat(32),
        "timeout_ms":3000
    }))
    .expect("route");
    value.binding_sha256 = authority_route_binding_sha256(&value).expect("route binding");
    value
}

pub fn identity_route() -> RemoteAuthorityRoute {
    let mut value = route();
    value.address = "127.0.0.1:7444".into();
    value.server_name = "identity.test".into();
    value.audience = "ihat-authority".into();
    value.authority_deployment_id = "identity-a".into();
    value.client_certificate_path = "/etc/crowsi/identity-client.der".into();
    value.client_certificate_sha256 = format!("sha256:{}", "8".repeat(64));
    value.client_private_key_path = "/etc/crowsi/identity-client.key".into();
    value.client_private_key_sha256 = format!("sha256:{}", "9".repeat(64));
    value.server_trust_anchor_path = "/etc/crowsi/identity-ca.der".into();
    value.server_trust_anchor_sha256 = format!("sha256:{}", "a".repeat(64));
    value.server_certificate_sha256 = format!("sha256:{}", "b".repeat(64));
    value.request_key_id = "identity-request-key".into();
    value.request_public_key_hex = "88".repeat(32);
    value.request_signing_key_path = "/etc/crowsi/identity-request.json".into();
    value.request_signing_key_sha256 = format!("sha256:{}", "c".repeat(64));
    value.response_key_id = "identity-response-key".into();
    value.response_public_key_hex = "99".repeat(32);
    value.binding_sha256 = authority_route_binding_sha256(&value).expect("identity binding");
    value
}
