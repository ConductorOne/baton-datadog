# baton-multipass-sdk (temporary local copy)

Temporary, trimmed copy of `github.com/conductorone/baton-multipass-sdk`
(`pkg/multipass`) at v0.0.1, commit b9f4b6776da475759bbcdc18f8209fedab389a6c.
The upstream module is private; this copy exists until it is public (IGA-5320).

Do not edit this code to diverge from upstream.

This directory is a package of the connector module
(`github.com/conductorone/baton-datadog/local_vendor/baton-multipass-sdk/pkg/multipass`),
not a nested module, so it builds and its tests run with the connector.

To swap in the public module (IGA-5320): delete `local_vendor/baton-multipass-sdk/`,
add `github.com/conductorone/baton-multipass-sdk` to the root `go.mod`, and change
the import path to `github.com/conductorone/baton-multipass-sdk/pkg/multipass` in
`pkg/connector/credential_output.go`, `credential_output_test.go`,
`credential_issue_actions_test.go`, `credential_org_key_smoke_test.go` and
`users.go`. Then run `go mod tidy && go mod vendor`.
