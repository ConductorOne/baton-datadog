# Datadog native `api_key_v2` preparation

The existing `API_KEY` issuance contract is raw plaintext: `application_key`
for a service account application key and `api_key` for an organization API
key. The connector still emits those bytes and advertises the existing
`service-account-application-key` and `api-key` resource type IDs. It has an
encoder for a future native arm for those keys, but does not advertise or
mint them as native values. The new native path issues a separate Datadog
service access token, described below.

## Payload mapping

`api_key_v2` is a Multipass `JsonV1` document. The connector encoder maps the
provider's one-time `Secret` to `key_value`, the provider's `ID` to `key_id`,
and uses `provider: "datadog"`. It sends `DD-APPLICATION-KEY` for a service
account application key and `DD-API-KEY` for an organization API key. Datadog
documents both headers in its [API reference](https://docs.datadoghq.com/api/latest/).
Only application keys can carry `scopes`, and those scopes must come from the
Datadog create response. An absent scopes response is omitted; a provider
reported empty set is encoded as `[]`. No `base_url` or `expires_at` is
asserted. A Datadog application key may still need a separate organization
API key for an endpoint; this one-value profile cannot provide the pair.

The schema and strict decoder are in Multipass
[`definitions.rs`](https://github.com/ductone/multipass/blob/f873f21b2353a72f28bd2bfd7b9b8c00ad07a317/crates/latchkey-client-sdk/src/secret_types/definitions.rs)
and [`codec.rs`](https://github.com/ductone/multipass/blob/f873f21b2353a72f28bd2bfd7b9b8c00ad07a317/crates/latchkey-client-sdk/src/secret_types/codec.rs).
The encoder test checks the exact declared field set and traverses a fake
Datadog create response through the official client. The SAT path has its own
fake-provider and Baton SDK encrypted-issuance fixtures. A temporary harness
at the pinned Multipass commit decoded the exact SAT plaintext obtained after
SDK encryption and decryption, then re-encoded it byte for byte. It also
rejected raw, missing-key, nested-value, and unknown-field controls. The run
used Nix Rust/Cargo 1.98.1 with the repository's locked dependencies; the
repository pins Rust 1.93.0 for its normal build.

## Why issuance remains raw

A native payload needs a distinct, durable `secret_resource_type_id` so C1
can associate that exact selector with `api_key_v2` before dispatch, and so
the connector can return the same resource type on later inventory syncs.
The current SDK requires an advertised discoverable issuance type to have a
registered lister and deleter. A new selector on Issue alone would fail that
contract. Listing the same provider keys under both raw and native resource
types would duplicate inventory and expose ambiguous revocation targets.

A name prefix does not solve the inventory split. Datadog permits name edits
for both [organization API keys](https://docs.datadoghq.com/api/latest/key-management/edit-an-api-key/)
and [service account application keys](https://docs.datadoghq.com/api/latest/service-accounts/edit-an-application-key-for-this-service-account/).
The list responses available to this connector include an ID, mutable name,
timestamps and key metadata, but no immutable creation-origin field. A rename
could move an existing key between two listers, or cause both to claim it.

The next design choice must provide a durable provider-ID to selector mapping
that sync can read, including after restart, or migrate an entire key kind to
native with an explicit compatibility plan for existing raw consumers. The
new selector must have its own discoverable lister and deleter, and C1 must
reject use by an executor that cannot consume the native payload **before**
the connector mints a provider key. No such selector is enabled for API or
application keys.

## Separate service access token path

Datadog [service access tokens](https://docs.datadoghq.com/account_management/service-access-tokens/)
are a distinct, standalone credential primitive. They have dedicated
`/api/v2/service_accounts/{id}/access_tokens` create, list, and revoke
endpoints, so they can use their own durable inventory selector without
partitioning either legacy key list. The opt-in
`service-account-access-token` resource type uses the `TOKEN` issuance shape
and emits native `api_key_v2` JSON. It is not an alternative representation
of an application key or an organization API key. Its `Authorization` header
name is truthful, but callers must add the Bearer scheme themselves because
the profile has no scheme field. Datadog's [create endpoint](https://docs.datadoghq.com/api/latest/service-accounts/create-an-access-token-for-a-service-account/)
requires scopes and returns the token key only on creation. The connector
uses the provider ID in `key_id` and provider-returned scopes, and records any
instant expiry on the resource trait instead of narrowing it to a date.

Inventory and revocation identify a SAT by its provider token ID plus owning
service-account ID. Renaming a SAT therefore leaves its synced resource ID
unchanged. A repeat issuance request is refused when the exact
`c1-<request-id>` name is still present. Datadog permits SAT renames, so
that name lookup cannot by itself guarantee deduplication after an administrator renames the
token. C1's mint-once request fence remains necessary; the connector never
retries a SAT create on an ambiguous transport result.
