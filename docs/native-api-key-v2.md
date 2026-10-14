# Datadog native credential action contract

The user resource publishes three dynamic actions. Each returns one encrypted
`api_key_v2` JSON secret and a public `issued_resource` handle. The existing
`IssueCredential` selectors remain available and continue returning raw key
bytes. These actions are pre-activation; the C1 credential-ticket adapter must
bind exact action names before any customer feature flag is enabled.

| Action | Secret return name | Provider object | Header name |
| --- | --- | --- | --- |
| `issue_service_account_application_key` | `application_key` | Service-account application key | `DD-APPLICATION-KEY` |
| `issue_organization_api_key` | `api_key` | Organization API key | `DD-API-KEY` |
| `issue_service_account_access_token` | `service_access_token` | Service access token | `Authorization` |

All actions take `user_id` as a Datadog user `ResourceId` and `request_id` as
the approved, stable credential ticket ID. Application-key `scopes` are
optional. SAT `scopes` are required, nonempty, and unique. Organization API
keys reject scopes. The handler checks inputs before any provider request. The
SDK encrypts named secret outputs to the caller's supplied recipient key; it
never places plaintext in the public action result or action status.

Each native document uses the provider's one-time key as `key_value`, stable
provider ID as `key_id`, and `datadog` as `provider`. It contains only scopes
reported by Datadog. The [Datadog SAT guide](https://docs.datadoghq.com/account_management/service-access-tokens/)
requires a `Bearer ` prefix when using the `Authorization` header; the
Multipass profile represents the header name but has no scheme field. The
application key may need a separate organization API key for Datadog API
calls. This action does not mint or copy that second key. The SAT is a
standalone credential. Provider instant expiry remains on the secret trait;
the date-only Multipass profile expiry is omitted.

`issued_resource` uses the same resource type and stable provider handle as
inventory and deletion. Application and organization keys retain their bare
provider IDs. SAT uses its service-account ID and token ID composite handle.
Provider rename changes display name, not the resource handle. Datadog permits
renaming all three credentials, so a provider name lookup cannot prove a
repeated ticket was never minted. C1 must enforce mint-once and treat an
ambiguous create, lost action ID, or post-mint encryption failure as an unknown
outcome. It must not automatically invoke again. C1 receives one encrypted
result, stores it under the `api_key_v2` profile through its existing
credential-ticket delivery path, and deletes the issued provider resource via
the existing resource deleter when needed.

The actions follow existing permission gates. `sync-secrets` plus
`sync-service-account-application-keys` offers application-key and SAT actions;
the latter setting attests Datadog `service_account_write` for both scoped
endpoints. `sync-secrets` plus `allow-org-api-key-deletion` offers the org-key
action. No new format or SAT flag exists. A 403 or 404 from SAT inventory fails
sync rather than implying the tokens were revoked.

The pinned Multipass
[`api_key_v2` codec](https://github.com/ductone/multipass/blob/f873f21b2353a72f28bd2bfd7b9b8c00ad07a317/crates/latchkey-client-sdk/src/secret_types/codec.rs)
requires `key_value` and rejects raw bytes, nested values, and unknown fields.
