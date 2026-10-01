pub fn approved_operation(
    prepared: &EndpointPreparedOperationV2,
    begin: &SignedAuthorityExchangeV1,
) -> ManagementOperationV2 {
    let mut value = operation(prepared, begin);
    let requirements = prepared
        .revocation
        .as_ref()
        .expect("revocation requirements");
    value.state = ManagementOperationState::AwaitingIndependentApproval;
    value.state_revision = 2;
    value.actor = ActorRequirementV2 {
        role: RequiredActorRole::IndependentApproval,
        required_actor_device_ref: None,
        required_approval_authority_ref: requirements.required_approval_authority_ref.clone(),
        excluded_actor_device_refs: vec![
            prepared.source_device_ref.clone(),
            requirements.target_device_ref.clone(),
        ],
    };
    value.webauthn_options = None;
    value
}
