# Using crowsi-device-credential-agent

Connect a managed device to the credential authority through the declared management contract.

## Before you start

Device registration, trust and deployment-specific transport are prerequisites supplied by the operator.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Validate device-management requests.
- Translate admitted requests into strict authority envelopes.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
