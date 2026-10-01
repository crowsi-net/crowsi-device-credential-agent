fn authentication(value: &FreshUvV1) -> FreshAuthenticationDto {
    FreshAuthenticationDto {
        proof_id: value.proof_id.clone(),
        authenticator_id: value.credential_id.clone(),
        authenticator_key_fingerprint: value.authenticator_key_fingerprint.clone(),
        kind: value.kind,
        user_verified: value.user_verified,
        issued_at_epoch_s: value.issued_at_epoch_s,
        expires_at_epoch_s: value.expires_at_epoch_s,
        service_id: value.service_id.clone(),
        pairwise_subject: value.pairwise_subject.clone(),
        session_ref: value.session_ref.clone(),
        operation_digest_sha256: value.operation_digest_sha256.clone(),
        subject_epoch: value.subject_epoch,
        service_epoch: value.service_epoch,
        device_epoch: value.device_epoch,
        session_epoch: value.session_epoch,
    }
}
