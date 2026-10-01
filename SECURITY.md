# Security boundary

The endpoint accepts only signed, closed config-v6 rooted at
`/etc/crowsi/device-credential-agent/root-trust.json`. Config-v6 pins separate
configuration, iHAT assertion, current-status, fresh-UV, session-sender,
recovery-approval, management-projection, credential-authority
request/response, iHAT-authority request/response, and PA-response roles.
Unknown fields and older config versions fail closed.

Config-v6 also pins the deployment-lifetime iHAT revocation-execution
reservation root independently from the central projection trust. The endpoint
verifies its immutable token before any irreversible revocation Final call.

The root signature also fixes the minimum accepted iHAT configuration
generation, the identity finalization authority, and the independent
revocation-approval authority. It also pins the account-bound WebAuthn
credential and account-binding digest used for fresh verification.
ManagementV2 callers cannot override any of them.

Authority access uses remote mTLS only. Each authority route binds the endpoint
and central deployment identities, server name, audience, device identity,
certificate and trust-anchor digests, request/response keys, timeout, and a
digest of the whole route. Credential and iHAT authorities must use different
deployment and key roles. The agent launches no authority subprocess and
endpoints never open or copy `FileAuthorityStore`.

Owner lookup is exactly `(issuer, service_id, pairwise_subject) -> opaque psa_`
from config-v6. Caller-selected owners, global account IDs, email addresses,
provider aliases, and raw pairwise subjects are not accepted as authority-store
identifiers.

Every accepted response is signed and bound to the exact request and command,
current device/session references, revocation epochs, posture revision, proof
key, and minimum snapshot revision. Durable projection revision state rejects
replay and rollback. An outage, signature failure, stale or mismatched
projection, unknown mapping, unknown field, oversized document, or timeout fails
closed.

For `SourceOptions`, the browser supplies only the management intent. The
endpoint derives the prepared operation from its latest verified snapshot and
root-signed policy, and iHAT selects the WebAuthn challenge for the one pinned
credential. The Begin request carries no caller proof. Selected identity,
prepared operation, exact Begin request, signed Begin response, exact central
envelope, and exact response bytes advance through one anchored journal.
Identity/Begin expiry is the minimum boundary; an expired or modified retry
never remints evidence under the same browser request ID.

For `SourceApprove`, the selected identity and Begin are historic immutable
receipts, while Finish and a separate current-identity exchange must be fresh
at submission. The endpoint requires one stable service, owner, device,
session, posture, epoch tuple, and session-sender role across that chain while
allowing only the current identity nonce to advance. Finish, current identity,
the central envelope, an ambiguous invocation, and the exact signed response
are distinct durable phases. Self-revocation additionally pins a central
pre-final acceptance, observes a second non-reused current identity, and
verifies the execution reservation under both pinned central trust and the
deployment-lifetime reservation root before iHAT Final. Once reserved, even a
first Final invocation and its cached response may recover after Begin expiry
under the pinned Begin response key. A changed WebAuthn assertion or request ID
cannot adopt an existing phase, and no phase failure remints a later request.

For independent `ApproveRevocation`, the browser supplies only its WebAuthn
assertion. The endpoint signs the 15-second recovery-approval proof with its
owner-only local key, then durably advances through an exact central pre-final
acceptance and a separate execution-reservation request. The reservation token
is verified with the deployment-lifetime reservation root and must have been
issued before the pinned Begin ceremony expired. Only after that signed token
and its exact Final request are committed may the endpoint invoke the
irreversible iHAT Final. A lost or delayed Final response is verified
historically against the durable reservation and pinned iHAT response key; its
arrival time may be after Begin expiry. The exact independent-finalize request
then completes the central operation. Pre-final and reservation material remain
only in the active journal; terminal refresh retains only the typed, exact
independent-finalize request.

Endpoint ratchets, the verified current iHAT session locator, enrollment
receipt, prepared/UV state, unknown-operation reconciliation journal, and
transport replay state share one closed namespaced durable ledger. Its state
and independent anchor directories are bound to the signed endpoint deployment
and configuration generation. Runtime startup cannot create or reset it;
installer-only initialization commits the genesis. Exact on-disk CAS prevents
stale concurrent identity evidence from restoring an earlier session.

Browser request-ID replay protection is deliberately bounded. Active records
retain exact indexes; terminal cleanup moves request ID, command digest,
operation ID, route, and any accepted response material into exact compact
receipts. Compact metadata is retained for at most 600 seconds, up to 32
receipts, while Cancel and Reconcile retain up to 16 exact tombstones each.
Capacity eviction may shorten that window. While metadata remains, a different
command under the same request ID fails closed. If response material is evicted
first by the 32 KiB material quota, the metadata still rejects both substituted
commands and unavailable exact replay.

Cancel refresh receipts are the exception to ordinary cached response
material. They retain a typed expected projection and, when cancellation
cleanup is required, the signed cleanup-delivery-complete proof. They are
charged directly to the 128 KiB operation-journal namespace and refresh a
current signed response instead of caching a response wrapper. Awaiting-Final
Cancel reserves a 96 KiB phase high-water allowance before its first external
side effect, compacts each D/E/Ack/delivery phase, and atomically retires the
active record and index only after delivery confirmation.

Refresh material is a closed typed value, not an opaque route/body pair.
Management envelopes and revocation-finalize requests are strictly decoded and
bound again to the original browser digest, operation, prepared evidence, and
peer before exact retransmission. A fresh signed response, management ratchet,
identity-locator observation, response bytes, and the sliding receipt deadline
commit atomically. New internal approval stages require a new closed material
variant and verifier; they cannot reuse an existing route variant.

After exact metadata expires or is evicted, the endpoint may accept the same
request ID as a new command. A still-retained central receipt then rejects a
digest collision; after both bounded stores have evicted it, the command is a
new request. The endpoint keeps no monotonic probabilistic accumulator: such an
accumulator would eventually reject every fresh ID and permanently stop
management. Callers should therefore generate unique request IDs even though
lifetime uniqueness is not asserted by the wire contract.

Client certificates, private keys, request/session-sender keys, PA config,
state, and the signed config must be canonical owner-controlled paths with the
modes specified in `docs/provisioning.md`. The root-trust file is canonical and
root-controlled. PA emits only exact, short-lived, one-use operation
authorization; the caller cannot create an action or custody request.
Compromise of one endpoint exposes only that endpoint's provisioned material;
central revocation remains required before it can no longer authenticate.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
