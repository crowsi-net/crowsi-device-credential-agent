mod rejection {
    use crowsi_credential_authority_contracts::{
        ManagementCommandV2, ManagementOperationState, ManagementProjectionBodyV2,
    };
    use crowsi_device_credential_agent::AgentError;

    use super::{Fixture, NOW, reach_central, support};

    #[test]
    fn approval_options_rejects_signed_lookup_actor_substitution() {
        let fixture = Fixture::new();
        let core = fixture.core();
        let prepared = support::prepared();
        let request = support::request("approval-options-lookup-actor", &prepared.operation_id);
        let wire = serde_json::to_vec(&request).expect("request");
        assert!(core.handle(&wire, NOW).is_err());
        let lookup_request = support::lookup_request(&fixture.requests());
        fixture.respond_lookup(
            support::lookup_response(&lookup_request, prepared),
            |value| value.actor_device_ref = "device-d".into(),
        );
        assert_eq!(
            core.handle(&wire, NOW),
            Err(AgentError::AuthorityResponseInvalid)
        );
    }

    #[test]
    fn approval_options_rejects_current_key_begin_below_generation_floor() {
        let fixture = Fixture::new();
        let prepared = support::prepared();
        let request = support::request("approval-options-begin-rollback", &prepared.operation_id);
        let wire = serde_json::to_vec(&request).expect("request");
        assert!(fixture.core().handle(&wire, NOW).is_err());
        let lookup_request = support::lookup_request(&fixture.requests());
        fixture.respond_lookup(support::lookup_response(&lookup_request, prepared), |_| {});
        let raised = fixture.raised_identity_generation_core(NOW);
        assert_eq!(
            raised.handle(&wire, NOW),
            Err(AgentError::AuthorityResponseInvalid)
        );
    }

    #[test]
    fn approval_options_rejects_wrong_actor_state_and_operation() {
        for case in 0..3 {
            let fixture = Fixture::new();
            let prepared = support::prepared();
            let request = support::request(
                &format!("approval-options-central-{case}"),
                &prepared.operation_id,
            );
            let (core, central) = reach_central(&fixture, &request);
            fixture.respond(&request, 4, |value| {
                let mut operation = support::actor_operation(&central);
                match case {
                    0 => operation.actor.required_actor_device_ref = Some("device-d".into()),
                    1 => {
                        operation.state = ManagementOperationState::AwaitingIndependentApproval;
                        operation.webauthn_options = None;
                    }
                    _ => operation.operation_id = "cd".repeat(32),
                }
                value.body = ManagementProjectionBodyV2::Operation { operation };
            });
            let wire = serde_json::to_vec(&request).expect("request");
            assert_eq!(
                core.handle(&wire, NOW),
                Err(AgentError::AuthorityResponseInvalid),
                "case {case}"
            );
        }
    }

    #[test]
    fn approval_options_rejects_browser_command_substitution() {
        let fixture = Fixture::new();
        let prepared = support::prepared();
        let request = support::request("approval-options-substitution", &prepared.operation_id);
        let (core, _) = reach_central(&fixture, &request);
        let mut changed = request;
        let ManagementCommandV2::ApprovalOptions {
            expected_state_revision,
            ..
        } = &mut changed.command
        else {
            unreachable!()
        };
        *expected_state_revision = 4;
        assert_eq!(
            core.handle(&serde_json::to_vec(&changed).expect("changed"), NOW),
            Err(AgentError::OperationReplay)
        );
    }
}
