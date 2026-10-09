# Datadog `api_key_v2` issuance contract

The three issuer selectors have distinct Datadog meanings:

| Secret resource type | Issue option | Datadog object | Header name |
| --- | --- | --- | --- |
| `service-account-application-key` | `API_KEY` | Application key owned by a service account | `DD-APPLICATION-KEY` |
| `api-key` | `API_KEY` | Organization API key | `DD-API-KEY` |
| `service-account-access-token` | `TOKEN` | Standalone service access token (SAT) | `Authorization` |

Each Issue arm emits one Multipass `api_key_v2` JsonV1 document on its existing
selector. It does not create a parallel native resource type, duplicate an
inventory row, or change the provider ID used for sync and revocation. The
service account application key and organization API key arms previously
emitted raw plaintext in released connector v0.4.0. Native vending is still
pre-release behind a C1 customer feature flag, not a connector payload flag; C1 must bind each exact
selector to `api_key_v2` only for compatible connector builds and refuse older
executors before minting. Existing stored raw credentials must not be
reinterpreted as typed documents.

## Fields

For all three kinds, the one-time provider key becomes `key_value`, the stable
provider ID becomes `key_id`, and `provider` is `datadog`. The encoder uses the
header names above. Datadog documents the API and application key headers in
its [API reference](https://docs.datadoghq.com/api/latest/), and the SAT
Bearer form in its [SAT guide](https://docs.datadoghq.com/account_management/service-access-tokens/).
The `Authorization` value needs a `Bearer ` prefix from the caller; the
Multipass profile has no scheme field.

The application-key arm includes `scopes` only when Datadog reports nonempty
scopes in its create response. The issued resource profile separately retains
the provider's distinction between absent and explicitly empty scopes. An
organization API key has no scopes. The SAT arm requires a nonempty set of
`TOKEN.scopes` before a provider call and includes only provider-reported
nonempty scopes in the payload. Datadog's [SAT create API](https://docs.datadoghq.com/api/latest/service-accounts/create-an-access-token-for-a-service-account/)
requires scopes. Neither API-key arm invents `base_url` or `expires_at`. A SAT
provider instant expiry is kept on SecretTrait; the profile's date-only
`expires_at` is omitted rather than losing time precision.

An application key may need an organization API key alongside it for Datadog
API authentication. The `api_key_v2` profile carries one key value; the
application-key arm does not mint or copy a second key from the connector's
management credentials. A SAT is a separate standalone credential and needs
no API-key pair.

## Lifecycle and inputs

The application-key and SAT arms target an actual service account, rechecked
at Issue time. Their synced resources retain service-account ownership. The
organization API key remains org-scoped; its provider `created_by` relationship
is kept distinct from the recipient identity. All three arms keep their
existing discoverable inventory and revoke path. SAT inventory/revoke uses a
stable composite of service-account ID and provider token ID, so a provider
rename changes only display name. App/API keys stay on their existing bare
provider IDs and resource types.

C1 must supply `API_KEY` plus the exact selected secret resource type for each
of the two API-key arms. It may supply requested scopes for a service-account
application key; organization API keys reject them. C1 must supply `TOKEN`
with a nonempty scopes list for SAT. Caller-selected SAT expiry is not
advertised by this connector, even though Datadog's endpoint supports it; a
request that asks for one fails before minting. The existing
`sync-service-account-application-keys` connector flag is off by default and
also requires `sync-secrets` and Datadog `service_account_write`. It activates
both application keys and SATs, whose scoped endpoints require that same
extra permission. No SAT-specific flag is needed. The organization-key grant
is unchanged.

The credential descriptors carry the cardinality rule: SAT advertises
`min_scopes = 1` with custom scopes allowed; the application key advertises
`min_scopes = 0` with optional custom scopes; the organization API key
advertises `min_scopes = 0`, no allowed scopes, and custom scopes disallowed.
The SDK's omitted/default minimum is zero. C1 can derive required, optional,
or unsupported scope input from the selected descriptor without recognizing
Datadog resource-type names. The connector also rejects missing SAT scopes
and unexpected organization-key scopes before any provider create call for
direct or older SDK callers.

This shared service-account setting now causes the connector to list SATs for
each active service account as well as application keys. A Datadog 403 or 404
from the SAT list endpoint fails the sync. It cannot be read as an empty
inventory: C1 would otherwise treat live tokens missing from a completed
sync as revoked. Before enabling the C1 feature flag for a site, verify that
the Datadog role has `service_account_write` and the SAT endpoint is
available there. The setting is off by default.

A repeated request is refused while the exact `c1-<request-id>` provider name
is present. Datadog permits renaming all three kinds, so name lookup does not
provide durable deduplication after an administrator rename. C1's mint-once
request fence remains necessary. Provider renames do not affect the stable
inventory IDs or revoke paths.

## Codec proof

The schema and strict decoder are in Multipass at pinned commit
[`f873f21`](https://github.com/ductone/multipass/blob/f873f21b2353a72f28bd2bfd7b9b8c00ad07a317/crates/latchkey-client-sdk/src/secret_types/definitions.rs)
and its [codec](https://github.com/ductone/multipass/blob/f873f21b2353a72f28bd2bfd7b9b8c00ad07a317/crates/latchkey-client-sdk/src/secret_types/codec.rs).
The SAT path was exercised through Baton SDK IssueCredential encryption and
JWK decryption, then the exact resulting bytes were decoded and re-encoded
byte-identically by the pinned Rust codec. Raw, missing-key, nested-value,
and unknown-field controls were rejected. The same end-to-end proof is
required for the two API-key arms before this contract is enabled. The Rust
run used Nix Rust/Cargo 1.98.1 with the pinned Cargo.lock; Multipass normally
pins Rust 1.93.0.
