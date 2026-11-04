// Copied from github.com/conductorone/baton-multipass-sdk/pkg/multipass v0.0.1
// (b9f4b677). Replace with that module once it is public (IGA-5320).

package multipass

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"unicode/utf8"
)

// ErrUnknownType reports a content type that names no type this package
// decodes, including a well-formed type ID that is not one of the five.
var ErrUnknownType = errors.New("multipass: unknown content type")

// fieldSpec lists the keys a type's document may carry and the ones it must.
// Both derive from the struct's JSON tags, so a field added there is decodable
// without a second list to keep in step.
type fieldSpec struct {
	allowed  map[string]struct{}
	required []string
}

var fieldSpecs = sync.OnceValue(func() map[string]fieldSpec {
	specs := make(map[string]fieldSpec, len(kindTags))
	for id, value := range typedValues {
		spec := fieldSpec{allowed: make(map[string]struct{})}
		typ := reflect.TypeOf(value)
		for i := range typ.NumField() {
			tag := typ.Field(i).Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			spec.allowed[name] = struct{}{}
			if !strings.Contains(opts, "omitempty") {
				spec.required = append(spec.required, name)
			}
		}
		specs[id] = spec
	}
	return specs
})

// typedValues holds one zero value per decodable type.
var typedValues = map[string]Typed{
	TypePasswordV2:          PasswordV2{},
	TypeAPIKeyV2:            APIKeyV2{},
	TypeSSHKey:              SSHKey{},
	TypeOAuthClientSecretV2: OAuthClientSecretV2{},
	TypeCertificate:         Certificate{},
}

// Decode reads a credential value and returns it as the type its content type
// names. contentType must be a Multipass MIME type; anything else returns
// ErrUnknownType.
//
// The document rules follow Multipass's JSON_V1 codec: it must be a UTF-8 JSON
// object, keys may not repeat, no key may carry null, and every required key
// must be present. Field content is not validated — Multipass rejects a bad URI
// or date itself, and a decoder that guessed at those rules would disagree with
// it. The codec's 512 KiB document cap is likewise not enforced here.
func Decode(contentType string, data []byte) (Typed, error) {
	id, ok := TypeIDFromContentType(contentType)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, contentType)
	}
	return decodeInto(id, data)
}

// DecodeAs reads a credential value as T, for a caller that already knows the
// type. The document is held to the same rules as Decode.
func DecodeAs[T Typed](data []byte) (T, error) {
	var zero T
	id := zero.MultipassTypeID()
	decoded, err := decodeInto(id, data)
	if err != nil {
		return zero, err
	}
	typed, ok := decoded.(T)
	if !ok {
		return zero, fmt.Errorf("multipass: decode %s: not a %T", id, zero)
	}
	return typed, nil
}

func decodeInto(id string, data []byte) (Typed, error) {
	value, ok := typedValues[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, id)
	}
	if err := checkDocument(id, data); err != nil {
		return nil, err
	}
	out := reflect.New(reflect.TypeOf(value))
	if err := json.Unmarshal(data, out.Interface()); err != nil {
		return nil, fmt.Errorf("multipass: decode %s: %w", id, err)
	}
	return out.Elem().Interface().(Typed), nil
}

// checkDocument applies the JSON_V1 rules Go's decoder does not: it keeps the
// last of a repeated key, accepts null for a scalar as its zero value, and
// replaces invalid UTF-8 instead of failing.
func checkDocument(id string, data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("multipass: decode %s: document is not valid UTF-8", id)
	}
	spec := fieldSpecs()[id]
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("multipass: decode %s: invalid JSON: %w", id, err)
	}
	if tok != json.Delim('{') {
		return fmt.Errorf("multipass: decode %s: not a JSON object", id)
	}
	seen := make(map[string]struct{}, len(spec.allowed))
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("multipass: decode %s: invalid JSON: %w", id, err)
		}
		key, _ := keyTok.(string)
		if _, repeated := seen[key]; repeated {
			return fmt.Errorf("multipass: decode %s: duplicate key %q", id, key)
		}
		seen[key] = struct{}{}
		if _, known := spec.allowed[key]; !known {
			return fmt.Errorf("multipass: decode %s: unknown key %q", id, key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("multipass: decode %s: invalid JSON for %q: %w", id, key, err)
		}
		if err := checkValue(key, raw); err != nil {
			return fmt.Errorf("multipass: decode %s: %w", id, err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("multipass: decode %s: invalid JSON: %w", id, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("multipass: decode %s: trailing data after the object", id)
	}
	for _, required := range spec.required {
		if _, present := seen[required]; !present {
			return fmt.Errorf("multipass: decode %s: missing required key %q", id, required)
		}
	}
	return nil
}

// checkValue rejects a null the codec refuses: on the key itself, or as an
// element of a list, where Go would otherwise substitute the zero value.
func checkValue(key string, raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("null value for %q", key)
	}
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return fmt.Errorf("invalid JSON for %q: %w", key, err)
	}
	for _, item := range items {
		if bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
			return fmt.Errorf("null value in %q", key)
		}
	}
	return nil
}
