// Package strictjson rejects ambiguous JSON before decoding a bounded schema.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// Decode accepts exactly one JSON value, rejects duplicate object keys at any
// depth and requires every typed object field to use its exact canonical name.
func Decode(data []byte, destination any) error {
	structure := json.NewDecoder(bytes.NewReader(data))
	structure.UseNumber()
	if err := scanValue(structure, reflect.TypeOf(destination)); err != nil {
		return err
	}
	if _, err := structure.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON must contain exactly one value")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode strict JSON: %w", err)
	}
	if err := requireEnd(decoder); err != nil {
		return err
	}
	return nil
}

func scanValue(decoder *json.Decoder, expected reflect.Type) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("read JSON value: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		return scanObject(decoder, expected)
	case '[':
		return scanArray(decoder, expected)
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func scanObject(decoder *json.Decoder, expected reflect.Type) error {
	expected, opaque := concreteJSONType(expected)
	var fields map[string]reflect.Type
	var element reflect.Type
	if !opaque && expected != nil {
		switch expected.Kind() {
		case reflect.Struct:
			fields = canonicalStructFields(expected)
		case reflect.Map:
			element = expected.Elem()
		}
	}

	seen := make(map[string]struct{})
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("read JSON field: %w", err)
		}
		name, ok := nameToken.(string)
		if !ok {
			return errors.New("JSON field name must be a string")
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("JSON repeats field %q", name)
		}
		seen[name] = struct{}{}

		fieldType := element
		if fields != nil {
			var known bool
			fieldType, known = fields[name]
			if !known {
				return fmt.Errorf("JSON field %q does not exactly match destination schema", name)
			}
		}
		if err := scanValue(decoder, fieldType); err != nil {
			return err
		}
	}
	return closeDelimiter(decoder, '}')
}

func scanArray(decoder *json.Decoder, expected reflect.Type) error {
	expected, opaque := concreteJSONType(expected)
	var element reflect.Type
	if !opaque && expected != nil && (expected.Kind() == reflect.Array || expected.Kind() == reflect.Slice) {
		element = expected.Elem()
	}
	for decoder.More() {
		if err := scanValue(decoder, element); err != nil {
			return err
		}
	}
	return closeDelimiter(decoder, ']')
}

func concreteJSONType(value reflect.Type) (reflect.Type, bool) {
	for value != nil {
		if value.Implements(jsonUnmarshalerType) || (value.Kind() != reflect.Pointer && reflect.PointerTo(value).Implements(jsonUnmarshalerType)) {
			return nil, true
		}
		if value.Kind() != reflect.Pointer {
			return value, false
		}
		value = value.Elem()
	}
	return nil, false
}

type fieldCandidate struct {
	valueType reflect.Type
	depth     int
	tagged    bool
}

func canonicalStructFields(value reflect.Type) map[string]reflect.Type {
	candidates := make(map[string][]fieldCandidate)
	collectStructFields(value, 0, make(map[reflect.Type]bool), candidates)

	fields := make(map[string]reflect.Type, len(candidates))
	for name, namedCandidates := range candidates {
		minimumDepth := namedCandidates[0].depth
		for _, candidate := range namedCandidates[1:] {
			if candidate.depth < minimumDepth {
				minimumDepth = candidate.depth
			}
		}

		var shallowest []fieldCandidate
		for _, candidate := range namedCandidates {
			if candidate.depth == minimumDepth {
				shallowest = append(shallowest, candidate)
			}
		}
		if len(shallowest) == 1 {
			fields[name] = shallowest[0].valueType
			continue
		}

		var tagged *fieldCandidate
		for index := range shallowest {
			if !shallowest[index].tagged {
				continue
			}
			if tagged != nil {
				tagged = nil
				break
			}
			tagged = &shallowest[index]
		}
		if tagged != nil {
			fields[name] = tagged.valueType
		}
	}
	return fields
}

func collectStructFields(value reflect.Type, depth int, active map[reflect.Type]bool, candidates map[string][]fieldCandidate) {
	value, opaque := concreteJSONType(value)
	if opaque || value == nil || value.Kind() != reflect.Struct || active[value] {
		return
	}
	active[value] = true
	defer delete(active, value)

	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		name, tagged, ignored := canonicalFieldName(field)
		if ignored {
			continue
		}
		fieldType, fieldOpaque := concreteJSONType(field.Type)
		promoted := field.Anonymous && !tagged && !fieldOpaque && fieldType != nil && fieldType.Kind() == reflect.Struct
		if promoted {
			collectStructFields(field.Type, depth+1, active, candidates)
			continue
		}
		if !field.IsExported() {
			continue
		}
		candidates[name] = append(candidates[name], fieldCandidate{
			valueType: field.Type,
			depth:     depth,
			tagged:    tagged,
		})
	}
}

func canonicalFieldName(field reflect.StructField) (string, bool, bool) {
	tag, present := field.Tag.Lookup("json")
	if present {
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			return "", false, true
		}
		if name != "" {
			return name, true, false
		}
	}
	return field.Name, false, false
}

func closeDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("close JSON value: %w", err)
	}
	if token != expected {
		return errors.New("JSON value is incomplete")
	}
	return nil
}

func requireEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("JSON must contain exactly one value")
}
