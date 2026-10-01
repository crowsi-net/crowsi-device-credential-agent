fn expected_revision(value: &crowsi_credential_authority_contracts::ManagementIntentV2) -> u64 {
    use crowsi_credential_authority_contracts::ManagementIntentV2 as Intent;
    match value {
        Intent::DeviceTransfer {
            expected_snapshot_revision,
            ..
        }
        | Intent::DeviceRevocation {
            expected_snapshot_revision,
            ..
        }
        | Intent::SessionRevocation {
            expected_snapshot_revision,
            ..
        } => *expected_snapshot_revision,
    }
}
