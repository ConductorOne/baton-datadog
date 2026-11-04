// Copied from github.com/conductorone/baton-multipass-sdk/pkg/multipass at b9f4b677.
// Replace with that module once it is public (<TICKET>).

package multipass

import (
	"encoding/json"
	"fmt"

	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

// OutputField declares the credential a descriptor returns: its content type,
// its tags, and that the value is a secret. Field.content_type is only defined
// for the string-shaped fields, so the oneof is set to an empty StringField.
func OutputField(name, id string) *configv1.Field {
	return configv1.Field_builder{
		Name:        name,
		ContentType: ContentType(id),
		Tags:        Tags(id),
		IsSecret:    true,
		StringField: configv1.StringField_builder{}.Build(),
	}.Build()
}

// Plaintext serializes v and sets the schema its type names, so the ciphertext
// carries the same content type.
func Plaintext(name string, v Typed) (*v2.PlaintextData, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("secret: encode %s: %w", v.MultipassTypeID(), err)
	}
	return v2.PlaintextData_builder{
		Name:   name,
		Schema: ContentType(v.MultipassTypeID()),
		Bytes:  encoded,
	}.Build(), nil
}
