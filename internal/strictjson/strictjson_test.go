package strictjson

import "testing"

func TestDecodeRejectsAmbiguousDocuments(t *testing.T) {
	t.Parallel()
	type nested struct {
		Value int `json:"value"`
	}
	type document struct {
		Name   string `json:"name"`
		Nested nested `json:"nested"`
	}

	var decoded document
	if err := Decode([]byte(`{"name":"ok","nested":{"value":1}}`), &decoded); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}

	for _, hostile := range []string{
		``,
		`[]`,
		`{"name":"a","name":"b","nested":{"value":1}}`,
		`{"name":"a","nested":{"value":1,"value":2}}`,
		`{"name":"a","nested":{"value":1},"unknown":true}`,
		`{"name":"a","nested":{"value":1}}{}`,
		`{"name":"a","nested":{"value":1}`,
	} {
		decoded = document{}
		if err := Decode([]byte(hostile), &decoded); err == nil {
			t.Fatalf("hostile document accepted: %s", hostile)
		}
	}
}

func TestDecodeRequiresExactCanonicalFieldNames(t *testing.T) {
	t.Parallel()
	type item struct {
		Tagged    int `json:"tagged"`
		Canonical int
		Ignored   string `json:"-"`
	}
	type document struct {
		Name   string          `json:"name"`
		Nested item            `json:"nested"`
		Items  []item          `json:"items"`
		ByName map[string]item `json:"by_name"`
	}

	valid := `{"name":"ok","nested":{"tagged":1,"Canonical":2},"items":[{"tagged":3,"Canonical":4}],"by_name":{"Arbitrary-Map-Key":{"tagged":5,"Canonical":6}}}`
	var decoded document
	if err := Decode([]byte(valid), &decoded); err != nil {
		t.Fatalf("valid exact document rejected: %v", err)
	}

	for _, hostile := range []string{
		`{"Name":"wrong case","nested":{"tagged":1,"Canonical":2},"items":[],"by_name":{}}`,
		`{"name":"ok","Nested":{"tagged":1,"Canonical":2},"items":[],"by_name":{}}`,
		`{"name":"ok","nested":{"Tagged":1,"Canonical":2},"items":[],"by_name":{}}`,
		`{"name":"ok","nested":{"tagged":1,"canonical":2},"items":[],"by_name":{}}`,
		`{"name":"ok","nested":{"tagged":1,"Canonical":2},"items":[{"Tagged":3,"Canonical":4}],"by_name":{}}`,
		`{"name":"ok","nested":{"tagged":1,"Canonical":2},"items":[],"by_name":{"free":{"Tagged":5,"Canonical":6}}}`,
		`{"name":"ok","nested":{"tagged":1,"Canonical":2,"Ignored":"forbidden"},"items":[],"by_name":{}}`,
		`{"name":"first","Name":"second","nested":{"tagged":1,"Canonical":2},"items":[],"by_name":{}}`,
	} {
		decoded = document{}
		if err := Decode([]byte(hostile), &decoded); err == nil {
			t.Fatalf("non-canonical field accepted: %s", hostile)
		}
	}
}
