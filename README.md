# Crowsi Device Credential Agent

`crowsi-device-credential-agent` is the finite, fail-closed endpoint for Crowsi
device and credential management. It accepts only the closed browser-facing
ManagementV2 request, derives private authority evidence locally, and sends a
strict internal envelope to an independently deployed credential authority using
remote mTLS only. It verifies the signed, request-bound projection before returning
it to Coela. No authority database or authority process is installed locally.

Production accepts only the closed
[`config-v6`](schemas/config-v6.schema.json) document signed with the key pinned
by `/etc/crowsi/device-credential-agent/root-trust.json`. Config-v6 binds two
separate remote mTLS routes for the credential and iHAT authorities, a finite
digest-pinned PA authorization route, the current identity/status/UV trust
roles, device-local session-sender and recovery-approval keys, exact
service/owner projection trust,
the exact account-bound WebAuthn credential and account-binding digest selected
for fresh verification,
the minimum signed iHAT config generation, fixed finalization and independent
revocation-approval authorities, the deployment-lifetime iHAT execution-
reservation root, device proof custody, and the deployment- and generation-
bound two-directory endpoint ledger. Earlier config versions and unknown fields
fail closed.

Owner lookup is the signed exact mapping
`(issuer, service_id, pairwise_subject) -> opaque psa_`. Private provider
credentials and the central `FileAuthorityStore` never enter config-v6 or the
endpoint. A compromised endpoint therefore cannot read another endpoint's key
material or mutate the authority store directly.

The supported routes are `snapshot`, `source-options`, `source-approve`,
`pending`, `target-options`, `target-approve`, `approval-options`,
`approve-revocation`, `cancel`, and `reconcile`. Each invocation reads one
closed ManagementV2 request from standard input and returns one verified
metadata-only projection.

`SourceOptions` is not a raw-forward route. The endpoint requires a current
signed snapshot, derives the exact prepared operation, durably fixes the one
empty-evidence iHAT Begin request before invoking it, and durably fixes the
signed Begin exchange plus central envelope before the central call. A lost
response retries those exact bytes. The signed Operation response must match
the prepared kind, scope, revision, source actor, and WebAuthn options; its
bytes and the projection ratchet commit together before return.

`SourceApprove` likewise never forwards a browser assertion as authority
evidence. It durably fixes the exact iHAT Finish request, verifies the signed
FreshUV result against the selected Begin, then durably fixes a distinct
submission-current identity request and the strict internal approval envelope.
Self-revocation then requires a signed central pre-final acceptance, a second
fresh current identity, and an immutable execution-reservation token before
the token-bound iHAT Final. Reserved Final and central finalize calls recover
from stored exact bytes even after Begin expiry; no pre-reservation phase can
cross that boundary.

An AwaitingRevocationFinal Cancel reserves its worst-case journal image before
the browser Cancel side effect. Execution cancellation, cancellation cleanup,
iHAT acknowledgement, and cleanup-delivery confirmation are each journaled
before invocation and compacted phase by phase. Only the final delivery proof
atomically retires the active Cancel record and index into typed refresh-only
receipt material.

Provisioning details are in [docs/provisioning.md](docs/provisioning.md). The
production transport has no development fallback and no local authority
subprocess.

## Verification

```sh
python3 -m unittest discover -s tests -p 'config_schema_*_test.py'
cargo fmt --all -- --check
cargo clippy --locked --offline --lib -- -D warnings
cargo test --offline
```
