# Datadog native `api_key_v2` preparation

The existing `API_KEY` issuance contract is raw plaintext: `application_key`
for a service account application key and `api_key` for an organization API
key. The connector still emits those bytes and advertises the existing
`service-account-application-key` and `api-key` resource type IDs. This change
adds an encoder for a future native arm, but does not advertise or mint one.

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
Datadog create response through the official client. A Rust execution of the
decoder is still needed before enabling a native selector; this environment
does not have `cargo`.

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
the connector mints a provider key. No such selector or gate is enabled here.
