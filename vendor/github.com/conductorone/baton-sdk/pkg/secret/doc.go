// Package secret serializes the values a connector issues under a Multipass
// content type. The structs match the field names Multipass decodes and do no
// validation: Multipass owns the schema, and a value it rejects must come back
// as its error rather than as a connector-side guess.
package secret
