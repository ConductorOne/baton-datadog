// Copied from github.com/conductorone/baton-multipass-sdk/pkg/multipass at b9f4b677.
// Replace with that module once it is public (<TICKET>).

// Package multipass serializes the values a connector issues under a Multipass
// content type. The structs match the field names Multipass decodes, mirroring
// crates/latchkey-client-sdk/src/secret_types/definitions.rs at
// ductone/multipass a5d4dad2dfb3a7ec820bf78fc7135ce6c8eda531. They do no
// validation: Multipass owns the schema, and a value it rejects must come back
// as its error rather than as a connector-side guess.
package multipass
