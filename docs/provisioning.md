# Exact production provisioning

1. Install the reviewed release binary on each Coela management endpoint. Coela
   pins its SHA-256 in its owner-only runtime document and invokes only the
   supported ManagementV2 route with `--config ABSOLUTE_PATH`.
2. Install `/etc/crowsi/device-credential-agent/root-trust.json` as a canonical,
   regular, root-owned file that is not writable by group or others. It contains
   only root-trust-v1, the configuration key ID, and its Ed25519 public key.
3. Create the closed config-v6 document defined by
   `schemas/config-v6.schema.json`. Sign the canonical
   `CROWSI-DEVICE-CREDENTIAL-CONFIG-V6` payload and install it as a canonical,
   endpoint-owner-controlled `0600` file. Its validity is at most 365 days.
4. Provision separate credential-authority and iHAT-authority routes. Both use
   remote mTLS only. Set each exact address, server name, audience, device ID, distinct
   endpoint and authority deployment IDs, timeout, client certificate/key,
   server trust anchor and certificate pins, request-signing key, response
   verification key, and route binding hash. There is no endpoint authority
   process or fallback transport.
   Pin `minimum_identity_config_generation`, `identity_finalization_authority_id`,
   `revocation_approval_authority_ref`, and the account-bound
   `user_verification_credential_id`, and its
   `user_verification_account_binding_sha256`; none is accepted from a browser
   request.
5. Install the client certificate, private key, trust anchor, and request-signing
   key at the absolute paths in config-v6. Each must be a canonical regular
   owner-controlled `0600` file whose SHA-256 equals its signed pin. Keep each
   endpoint's client and request keys unique and non-exportable where supported.
6. Provision the finite PA authorization executable and owner config by exact
   path and digest. Pin its independent response key. It may authorize only the
   exact TargetApprove Ed25519 operation derived from signed iHAT, UV, prepared
   operation, and target custody evidence; it has no generic custody action.
7. Pin `ManagementProjectionTrust` to the exact issuer, audience, service-local
   subject and opaque account, current device, minimum revocation epochs,
   compliant posture revision, device proof key, minimum snapshot revision, and
   projection verification key expected for this endpoint. Current session is
   resolved from iHAT and is not fixed in config.
8. Provision only exact owner mappings of iHAT issuer, service-local pairwise
   subject, and opaque `psa_` owner reference. Do not provision email, global
   identity, provider account aliases, or caller-selected owners.
9. Provision exactly one device proof mapping completely: owner, device, proof-key
   reference and public key, non-exportable custody type, digest-pinned custody
   provider path, credential ID, and expected revision. Private device keys and
   provider credentials never enter config-v6.
10. Install a device-local session-sender key distinct from every transport,
    proof, status, UV, PA, and response key. Pin its fingerprint and file digest.
    Install the separate recovery-approval Ed25519 key in its closed v1 JSON
    document. Pin its key ID, public key, fingerprint, absolute private-key path,
    and file SHA-256 in config-v6. Its canonical parent directory must be owned
    by the endpoint service account with mode `0700`; the key file must be a
    single-link regular file owned by that account with mode `0600`. Keep this
    key ID, material, and path distinct from every other configured role.
    Pin the deployment-lifetime iHAT revocation-execution-reservation root key
    ID and public key, plus its minimum reservation config generation. This key
    is distinct from the central projection key and every other endpoint role;
    it verifies the immutable execution token before any Final side effect.
    Set the root-signed `endpoint_deployment_id` equal to both remote route
    deployment IDs and set a positive, monotonically increasing
    `configuration_generation`. Create the exact `endpoint_state_directory` and independent
    `endpoint_anchor_directory` as canonical endpoint-owner-controlled `0700`
    directories. They store only endpoint ratchets, journals, and the current
    opaque iHAT session locator; they never store the central authority database.
11. Atomically install the signed config, update Coela's runtime document with
    its path and the agent digest, then restart Coela. Missing, invalid, stale,
    mismatched, or unavailable dependencies keep management unavailable.

The endpoint obtains current iHAT identity, status, and fresh-verification
exchanges over its separately pinned mTLS route and sends only the closed signed
evidence envelope to the central authority. Only the central authority opens
`FileAuthorityStore`; never replicate that authority state to endpoints.

## Durable endpoint-state activation

Config-v6 replaces the legacy state paths with exactly two pairwise-distinct,
absolute paths: `endpoint_state_directory` and `endpoint_anchor_directory`. The
installer creates both as `0700` directories owned by the endpoint account and
invokes the finite `initialize-once` path as that account. Initialization binds
the ledger to the root-signed `endpoint_deployment_id` and
`configuration_generation`, seals both directories, and commits an empty
namespaced genesis generation. An exact retry is idempotent.

Normal management startup only opens this sealed ledger. It never initializes
empty directories. It receives the trusted process EUID separately and rejects
a directory-declared owner, a missing genesis, a deployment or configuration
downgrade, and any unknown file or namespace. The state and anchor directory
file descriptors stay pinned for each locked transaction.

The closed namespaces are `management-projection`,
`identity-session-locator`, `device-enrollment`, `prepared-operation`,
`fresh-uv-attempt`, `operation-journal`, and `transport-replay`. A transaction
may update several namespaces in one immutable generation. `device-enrollment`
is provisioning-only; normal ManagementV2 routing cannot write it.
Each namespace has a closed byte, collection-item, node-count, and nesting-depth
quota; the whole canonical map is capped below the ledger file limit. Quota
exhaustion rejects the transaction and never evicts the active enrollment or
identity locator.

Browser request IDs have a bounded replay window. Active operations keep exact
indexes. Terminal browser artifacts become exact compact receipt metadata for
at most 600 seconds, capped at 32 entries; Cancel and Reconcile tombstones are
separately capped at 16 entries each. Oldest-entry capacity eviction can end the
window earlier. Ordinary cached response material has a 32 KiB budget:
material eviction keeps metadata fail-closed until metadata itself expires or
is evicted. Typed Cancel refresh material is charged directly to the 128 KiB
operation-journal namespace instead and does not retain a signed response
wrapper. After retention ends, same-ID/different-command reuse is allowed by
the endpoint wire contract and is still subject to any central receipt that
remains. Provision callers with high-entropy, practically unique request IDs;
do not treat endpoint retention as a lifetime uniqueness registry.

Retained refresh material is typed per internal protocol. Management envelopes
and revocation-finalize requests are strictly revalidated against their browser
request, operation, prepared evidence, and configured peer before replay. A
fresh response and the management, locator, material, and retention ratchets
commit together. Material eviction preserves only fail-closed metadata.

`SourceOptions` updates `prepared-operation`, `fresh-uv-attempt`, and
`operation-journal` atomically before iHAT invocation. After iHAT commits, the
same transaction records the signed exchange and strict central envelope. The
central response and `management-projection` ratchet then commit together.
Restart resumes only the stored request/envelope; it cannot generate new IDs,
challenges, prepared nonces, or evidence for the same browser request ID.

`SourceApprove` adds a second closed record under `operation-journal`. Before
each external call it stores the full exact Finish request, then the full exact
submission-current identity request, then the strict central envelope. For
self-revocation it next stores central pre-final acceptance, a distinct fresh
reservation identity, the exact execution-reserve request, the dual-signed
reservation, its token-attached Final, and the v2 finalize request. Before the
reservation, expiry is the minimum live evidence and Begin boundary. After the
reservation, Final Prepared/Invoking/Unknown and finalize recovery use pinned
historic trust and never remint exact request bytes.

Independent revocation adds closed pre-final, execution-reservation, iHAT
Final, and independent-finalize phases. Each outbound request is committed
before invocation, and an ambiguous result retries only its stored bytes. A
fresh finalizer identity is observed before the execution reservation is
requested. The signed reservation fixes the finalizer device and exact Final
command, and the endpoint verifies both its fresh outer management signature
and its immutable reservation-root token before persisting the token-attached
Final request. Once reserved, recovery can cross the Begin and token expiry
boundaries; before reservation, Begin expiry requires cancellation and a new
ceremony. Terminal cleanup retains only the typed independent-finalize request
and response needed for bounded exact refresh.

Cancelling an operation that is awaiting revocation Final reserves a 96 KiB
phase high-water allowance before the browser Cancel call. The endpoint then
persists every execution-cancel, cancel-finalize, iHAT acknowledgement, and
cleanup-delivery-complete call as Prepared, Invoking, or Unknown before an
external side effect. Each transition compacts the previous phase and
rebalances the remaining allowance against the actual serialized record. Only
an accepted cleanup-delivery-complete proof may atomically replace the active
Cancel record and its index with typed refresh-only receipt material.

Every generation and anchor is immutable, content-addressed, owner-only `0600`,
and linked to the previous retained revision. A durable intent precedes writes.
After a crash, an incomplete one-sided pair is discarded, while a complete
pair is forward-finished to both heads. Pruning happens only after both heads
commit. Unknown or unjournaled state/anchor asymmetry, stale temporary files,
tamper, and rollback fail closed.
