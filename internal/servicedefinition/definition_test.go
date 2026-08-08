package servicedefinition

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	// The inputs of the reference vector. It is the definition of the synthetic
	// application the proof of this milestone deploys — two volumes, one tmpfs,
	// three inert lines one of which interpolates the origin, one generated
	// secret — so that the vector proves the encoding of the shape the proof
	// actually exercises rather than of a shape nothing uses.
	vectorSlug            = "lab-notes"
	vectorImageRepository = "registry.lab.your-cloud.test/your-cloud/lab-notes"
	vectorContainerPort   = 8080
	vectorDataVolume      = "/srv/notes"
	vectorStateVolume     = "/var/lib/lab-notes"
	vectorScratchTmpfs    = "/tmp"
	vectorTitleLine       = "LAB_NOTES_TITLE=Your Cloud lab notes"
	vectorOriginLine      = "LAB_NOTES_ORIGIN=https://{origin_host}/"
	vectorReadOnlyLine    = "LAB_NOTES_READ_ONLY=1"
	vectorSecretKey       = "LAB_NOTES_ADMIN_TOKEN"

	// The inputs of the minimal vector: a definition that declares none of the
	// four lists. It exists so that the empty count is pinned across the two
	// implementations too, and it carries a low container port because that is
	// the case a later palier reads a sysctl off.
	vectorMinimalSlug            = "minimal"
	vectorMinimalImageRepository = "registry.lab.your-cloud.test/minimal"
	vectorMinimalContainerPort   = 80

	// The two canonical documents, byte for byte. A transport may reindent them;
	// the Controller emits exactly these bytes, and re-reading a frozen
	// definition returns exactly these bytes.
	vectorReferenceDocument = `{"schema_version":1,"slug":"lab-notes",` +
		`"image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
		`"container_port":8080,"volumes":["/srv/notes","/var/lib/lab-notes"],` +
		`"tmpfs":["/tmp"],"environment":["LAB_NOTES_TITLE=Your Cloud lab notes",` +
		`"LAB_NOTES_ORIGIN=https://{origin_host}/","LAB_NOTES_READ_ONLY=1"],` +
		`"secret_keys":["LAB_NOTES_ADMIN_TOKEN"]}`
	vectorMinimalDocument = `{"schema_version":1,"slug":"minimal",` +
		`"image_repository":"registry.lab.your-cloud.test/minimal",` +
		`"container_port":80,"volumes":[],"tmpfs":[],"environment":[],"secret_keys":[]}`

	// The two transcripts, byte for byte. The Rust side of this palier must
	// reproduce these exact vectors from its own encoder: a canonical encoding
	// that exists in two implementations is only canonical while the two agree
	// byte for byte, and a drift caught here is a drift that never reaches a
	// machine as a definition the other side hashes differently.
	vectorReferenceTranscriptHex = "796f75722d636c6f75642f736572766963652d646566696e6974696f6e2e7631" +
		"0001000000096c61622d6e6f7465730000003172656769737472792e6c61622e" +
		"796f75722d636c6f75642e746573742f796f75722d636c6f75642f6c61622d6e" +
		"6f74657300001f90000000020000000a2f7372762f6e6f746573000000122f76" +
		"61722f6c69622f6c61622d6e6f74657300000001000000042f746d7000000003" +
		"000000244c41425f4e4f5445535f5449544c453d596f757220436c6f7564206c" +
		"6162206e6f746573000000274c41425f4e4f5445535f4f524947494e3d687474" +
		"70733a2f2f7b6f726967696e5f686f73747d2f000000154c41425f4e4f544553" +
		"5f524541445f4f4e4c593d3100000001000000154c41425f4e4f5445535f4144" +
		"4d494e5f544f4b454e"
	vectorMinimalTranscriptHex = "796f75722d636c6f75642f736572766963652d646566696e6974696f6e2e7631" +
		"0001000000076d696e696d616c0000002472656769737472792e6c61622e796f" +
		"75722d636c6f75642e746573742f6d696e696d616c0000005000000000000000" +
		"000000000000000000"

	// The two digests a plan of this milestone names as definition_digest, in the
	// exact spelling that field requires.
	vectorReferenceSHA256 = "c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce"
	vectorMinimalSHA256   = "faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c"
)

func vectorReference() Document {
	return Document{
		SchemaVersion:   SchemaVersion,
		Slug:            vectorSlug,
		ImageRepository: vectorImageRepository,
		ContainerPort:   vectorContainerPort,
		Volumes:         []string{vectorDataVolume, vectorStateVolume},
		Tmpfs:           []string{vectorScratchTmpfs},
		Environment:     []string{vectorTitleLine, vectorOriginLine, vectorReadOnlyLine},
		SecretKeys:      []string{vectorSecretKey},
	}
}

func vectorMinimal() Document {
	return Document{
		SchemaVersion:   SchemaVersion,
		Slug:            vectorMinimalSlug,
		ImageRepository: vectorMinimalImageRepository,
		ContainerPort:   vectorMinimalContainerPort,
	}
}

// hostileDefinitionDocument encodes a document without validating it, which is
// what a hostile test needs: the refusal under test must come from the decoder
// rather than from the encoder refusing to produce the bytes in the first place.
func hostileDefinitionDocument(t *testing.T, document Document) []byte {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodedHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func keysOf[value any](table map[string]value) map[string]struct{} {
	names := make(map[string]struct{}, len(table))
	for name := range table {
		names[name] = struct{}{}
	}
	return names
}

// TestDeterministicDefinitionVectorsAreHeldWithTheRustSide is the
// interoperability proof of the definition encoding.
//
// Every transcript, every digest and every canonical document is pinned here
// literally. The Rust implementation of this milestone pins the same values from
// its own encoder, so a single byte of drift in either implementation fails here
// rather than producing definitions the other side hashes differently — which,
// on a real machine, is an Auxiliary refusing a plan the Controller froze.
func TestDeterministicDefinitionVectorsAreHeldWithTheRustSide(t *testing.T) {
	t.Parallel()
	for _, subject := range []struct {
		name             string
		document         Document
		canonical        string
		transcript       string
		digest           string
		transcriptLength int
	}{
		{
			name:             "reference definition",
			document:         vectorReference(),
			canonical:        vectorReferenceDocument,
			transcript:       vectorReferenceTranscriptHex,
			digest:           vectorReferenceSHA256,
			transcriptLength: 297,
		},
		{
			name:             "definition without lists",
			document:         vectorMinimal(),
			canonical:        vectorMinimalDocument,
			transcript:       vectorMinimalTranscriptHex,
			digest:           vectorMinimalSHA256,
			transcriptLength: 105,
		},
	} {
		encoded, err := subject.document.Encode()
		if err != nil {
			t.Fatalf("%s: %v", subject.name, err)
		}
		if string(encoded) != subject.canonical {
			t.Fatalf("%s canonical document drifted:\n%s", subject.name, encoded)
		}

		transcript, err := subject.document.Transcript()
		if err != nil {
			t.Fatalf("%s: %v", subject.name, err)
		}
		if len(transcript) != subject.transcriptLength {
			t.Fatalf("%s transcript length drifted: %d", subject.name, len(transcript))
		}
		if !bytes.Equal(transcript, decodedHex(t, subject.transcript)) {
			t.Fatalf("%s transcript drifted from the shared vector:\n%s",
				subject.name, hex.EncodeToString(transcript))
		}
		if !strings.HasPrefix(string(transcript), TranscriptDomain) {
			t.Fatalf("%s transcript does not open on its own domain separator", subject.name)
		}

		digest, err := subject.document.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", subject.name, err)
		}
		if digest != subject.digest {
			t.Fatalf("%s digest drifted: %s", subject.name, digest)
		}

		// The round trip is part of the vector rather than a test of its own: a
		// definition read back from its canonical bytes is the same definition,
		// down to the digest a plan pinned.
		decoded, err := Decode([]byte(subject.canonical))
		if err != nil {
			t.Fatalf("%s did not decode its own canonical bytes: %v", subject.name, err)
		}
		reencoded, err := decoded.Encode()
		if err != nil {
			t.Fatalf("%s: %v", subject.name, err)
		}
		if string(reencoded) != subject.canonical {
			t.Fatalf("%s did not return the bytes it was frozen with:\n%s", subject.name, reencoded)
		}
		roundTripDigest, err := decoded.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", subject.name, err)
		}
		if roundTripDigest != subject.digest {
			t.Fatalf("%s changed digest across a round trip: %s", subject.name, roundTripDigest)
		}
	}

	if vectorReferenceSHA256 == vectorMinimalSHA256 {
		t.Fatal("the two vectors of this palier share a digest")
	}
}

// TestAlteringOneByteOfACanonicalDefinitionNeverKeepsItsDigest is the property
// the whole trajectory of the document rests on.
//
// The Auxiliary rehashes the bytes it receives before reading anything of the
// machine, and refuses them when the digest is not the definition_digest of the
// plan. That refusal is only worth something if no altered document can keep the
// digest, so the statement is made exhaustively rather than on a chosen byte:
// every single-byte alteration of the canonical reference either stops decoding
// or produces another digest, and never a second document under the first
// digest.
func TestAlteringOneByteOfACanonicalDefinitionNeverKeepsItsDigest(t *testing.T) {
	t.Parallel()
	original := []byte(vectorReferenceDocument)
	for position := range original {
		for _, replacement := range []byte{'a', 'z', '0', '9', '-', '/'} {
			if original[position] == replacement {
				continue
			}
			altered := make([]byte, len(original))
			copy(altered, original)
			altered[position] = replacement

			decoded, err := Decode(altered)
			if err != nil {
				continue
			}
			digest, err := decoded.SHA256()
			if err != nil {
				t.Fatalf("byte %d replaced by %q: %v", position, replacement, err)
			}
			if digest == vectorReferenceSHA256 {
				t.Fatalf("byte %d replaced by %q kept the digest of the reference: %s",
					position, replacement, altered)
			}
		}
	}

	// And the original is still readable beside every one of those alterations,
	// which is the other half of what the proof states: an altered definition is
	// refused and the one that was frozen stays exactly what it was.
	decoded, err := Decode(original)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := decoded.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if digest != vectorReferenceSHA256 {
		t.Fatalf("the original definition no longer carries its digest: %s", digest)
	}
}

// TestEveryFieldOfADefinitionIsInsideTheHashedBytes is the central property of
// the transcript.
//
// A field that could move without moving the digest would be a field the
// Controller owns, since the Controller is the only thing between the human who
// approved a plan and the machine that performs it. The canonical document is
// read back at the end so that a field added to the schema and forgotten in the
// transcript fails here rather than in a later palier.
func TestEveryFieldOfADefinitionIsInsideTheHashedBytes(t *testing.T) {
	t.Parallel()
	moves := map[string]func(*Document){
		"schema_version":   func(d *Document) { d.SchemaVersion = SchemaVersion + 1 },
		"slug":             func(d *Document) { d.Slug = "other-notes" },
		"image_repository": func(d *Document) { d.ImageRepository = "registry.lab.your-cloud.test/other" },
		"container_port":   func(d *Document) { d.ContainerPort = vectorContainerPort + 1 },
		"volumes":          func(d *Document) { d.Volumes = []string{vectorDataVolume} },
		"tmpfs":            func(d *Document) { d.Tmpfs = nil },
		"environment":      func(d *Document) { d.Environment = []string{vectorTitleLine} },
		"secret_keys":      func(d *Document) { d.SecretKeys = nil },
	}
	reference := rawTranscript(t, vectorReference())
	for field, move := range moves {
		moved := vectorReference()
		move(&moved)
		if bytes.Equal(rawTranscript(t, moved), reference) {
			t.Fatalf("%s is outside the hashed bytes", field)
		}
	}

	var onTheWire map[string]json.RawMessage
	if err := json.Unmarshal([]byte(vectorReferenceDocument), &onTheWire); err != nil {
		t.Fatal(err)
	}
	held := keysOf(moves)
	for field := range onTheWire {
		if _, covered := held[field]; !covered {
			t.Fatalf("the canonical document carries %q and no move of this test touches it", field)
		}
	}
	if len(onTheWire) != len(held) {
		t.Fatalf("the schema carries %d fields on the wire and this test moves %d",
			len(onTheWire), len(held))
	}
}

// rawTranscript builds the hashed bytes of a document that a test has
// deliberately moved out of the contract, so that the statement under test is
// about the layout rather than about validation refusing the subject first.
func rawTranscript(t *testing.T, document Document) []byte {
	t.Helper()
	transcript := append([]byte(nil), TranscriptDomain...)
	transcript = append(transcript, byte(document.SchemaVersion))
	transcript = appendField(transcript, []byte(document.Slug))
	transcript = appendField(transcript, []byte(document.ImageRepository))
	transcript = appendUint32(transcript, uint32(document.ContainerPort))
	transcript = appendList(transcript, document.Volumes)
	transcript = appendList(transcript, document.Tmpfs)
	transcript = appendList(transcript, document.Environment)
	return appendList(transcript, document.SecretKeys)
}

// TestTwoDefinitionsDifferingOnlyByTheOrderOfAListAreTwoDefinitions pins the
// decision the layout rests on.
//
// The order of a list is inside the hashed bytes, so a Controller, a transport
// or a Console that reordered a list would be handing an Auxiliary a document no
// approval names. Freezing what the author wrote — rather than a sorted
// rewriting of it — is what makes re-reading a frozen definition return the
// bytes that were frozen.
func TestTwoDefinitionsDifferingOnlyByTheOrderOfAListAreTwoDefinitions(t *testing.T) {
	t.Parallel()
	for name, reorder := range map[string]func(*Document){
		"the two volumes": func(d *Document) { d.Volumes = []string{vectorStateVolume, vectorDataVolume} },
		"the environment lines": func(d *Document) {
			d.Environment = []string{vectorReadOnlyLine, vectorOriginLine, vectorTitleLine}
		},
	} {
		reordered := vectorReference()
		reorder(&reordered)
		digest, err := reordered.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest == vectorReferenceSHA256 {
			t.Fatalf("reordering %s left the digest where it was", name)
		}
		encoded, err := reordered.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(encoded) == vectorReferenceDocument {
			t.Fatalf("reordering %s left the canonical bytes where they were", name)
		}
	}
}

// TestAListLeftOutIsTheSameDefinitionAsAnEmptyOne states the one place where two
// spellings are accepted and freeze to one.
//
// A list nobody declared, a list spelled null and a list spelled empty describe
// the same state — no volume, no tmpfs, no line, no key — so they are one
// definition with one digest, and the canonical spelling of all three is the
// empty array. Nothing else in the document has a second accepted spelling.
func TestAListLeftOutIsTheSameDefinitionAsAnEmptyOne(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"the four lists left out": `{"schema_version":1,"slug":"minimal",` +
			`"image_repository":"registry.lab.your-cloud.test/minimal","container_port":80}`,
		"the four lists spelled null": `{"schema_version":1,"slug":"minimal",` +
			`"image_repository":"registry.lab.your-cloud.test/minimal","container_port":80,` +
			`"volumes":null,"tmpfs":null,"environment":null,"secret_keys":null}`,
		"the four lists spelled empty": vectorMinimalDocument,
	} {
		decoded, err := Decode([]byte(document))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		encoded, err := decoded.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(encoded) != vectorMinimalDocument {
			t.Fatalf("%s froze to another spelling:\n%s", name, encoded)
		}
		digest, err := decoded.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest != vectorMinimalSHA256 {
			t.Fatalf("%s carries another digest: %s", name, digest)
		}
	}
}

// TestTheBoundsOfADefinitionAreThemselvesAccepted keeps every refusal of the
// hostile tables below naming a malformation rather than an off-by-one.
func TestTheBoundsOfADefinitionAreThemselvesAccepted(t *testing.T) {
	t.Parallel()
	for name, shape := range map[string]func(*Document){
		"shortest slug":          func(d *Document) { d.Slug = "a" },
		"longest slug":           func(d *Document) { d.Slug = strings.Repeat("a", MaxSlugChars) },
		"slug of digits":         func(d *Document) { d.Slug = "42" },
		"lowest container port":  func(d *Document) { d.ContainerPort = MinContainerPort },
		"highest container port": func(d *Document) { d.ContainerPort = MaxContainerPort },
		"registry on a port": func(d *Document) {
			d.ImageRepository = "registry.lab.your-cloud.test:5000/your-cloud/lab-notes"
		},
		"single path component": func(d *Document) {
			d.ImageRepository = "registry.lab.your-cloud.test/lab-notes"
		},
		"repository carrying dots and underscores": func(d *Document) {
			d.ImageRepository = "registry.lab.your-cloud.test/your_cloud/lab.notes-2"
		},
		"eight volumes and eight tmpfs": func(d *Document) {
			d.Volumes = numberedPaths("/srv/volume", MaxVolumes)
			d.Tmpfs = numberedPaths("/run/scratch", MaxTmpfs)
		},
		"neighbours that do not open one another": func(d *Document) {
			d.Volumes = []string{"/srv", "/srvdata", "/srv-notes"}
			d.Tmpfs = []string{"/srvx"}
		},
		"longest container path": func(d *Document) {
			d.Volumes = []string{"/" + strings.Repeat("a", MaxContainerPathBytes-1)}
			d.Tmpfs = nil
		},
		"path carrying dots inside a segment": func(d *Document) {
			d.Volumes = []string{"/srv/notes.d/v1.2"}
			d.Tmpfs = nil
		},
		"thirty-two environment lines": func(d *Document) { d.Environment = numberedEnvironment(MaxEnvironmentLines) },
		"sixteen secret keys":          func(d *Document) { d.SecretKeys = numberedKeys("SECRET", MaxSecretKeys) },
		"longest environment key": func(d *Document) {
			d.Environment = []string{"A" + strings.Repeat("B", MaxEnvironmentKeyChars-1) + "=1"}
		},
		"longest environment value": func(d *Document) {
			d.Environment = []string{"LONG=" + strings.Repeat("x", MaxEnvironmentValueBytes)}
		},
		"empty environment value": func(d *Document) { d.Environment = []string{"EMPTY="} },
		"value carrying separators": func(d *Document) {
			d.Environment = []string{`SPELLING=a=b c;d "e" \f/g`}
		},
		"the origin interpolated twice": func(d *Document) {
			d.Environment = []string{"BOTH=https://{origin_host}/ and {origin_host}"}
		},
		"no secret key at all": func(d *Document) { d.SecretKeys = nil },
	} {
		document := vectorReference()
		shape(&document)
		if _, err := Decode(hostileDefinitionDocument(t, document)); err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
	}
}

func numberedPaths(prefix string, count int) []string {
	paths := make([]string, 0, count)
	for index := 0; index < count; index++ {
		paths = append(paths, fmt.Sprintf("%s-%d", prefix, index))
	}
	return paths
}

func numberedKeys(prefix string, count int) []string {
	keys := make([]string, 0, count)
	for index := 0; index < count; index++ {
		keys = append(keys, fmt.Sprintf("%s_%d", prefix, index))
	}
	return keys
}

func numberedEnvironment(count int) []string {
	lines := make([]string, 0, count)
	for _, key := range numberedKeys("LINE", count) {
		lines = append(lines, key+"=value")
	}
	return lines
}

// TestDecodeRefusesEveryDefinitionOutsideTheContract is the hostile table of the
// document: every named refusal of the contract, exercised by its own subject.
func TestDecodeRefusesEveryDefinitionOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := Decode([]byte(vectorReferenceDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}

	for name, mutate := range map[string]func(*Document){
		"schema version zero":    func(d *Document) { d.SchemaVersion = 0 },
		"schema version to come": func(d *Document) { d.SchemaVersion = SchemaVersion + 1 },
		"negative schema":        func(d *Document) { d.SchemaVersion = -1 },

		"empty slug":               func(d *Document) { d.Slug = "" },
		"slug of seventeen":        func(d *Document) { d.Slug = strings.Repeat("a", MaxSlugChars+1) },
		"upper-case slug":          func(d *Document) { d.Slug = "Lab-Notes" },
		"slug opening on a hyphen": func(d *Document) { d.Slug = "-lab-notes" },
		"slug carrying a dot":      func(d *Document) { d.Slug = "lab.notes" },
		"slug carrying a slash":    func(d *Document) { d.Slug = "lab/notes" },
		"slug carrying a space":    func(d *Document) { d.Slug = "lab notes" },
		"slug climbing":            func(d *Document) { d.Slug = "../etc" },

		"repository carrying a tag": func(d *Document) {
			d.ImageRepository = vectorImageRepository + ":latest"
		},
		"repository carrying a digest": func(d *Document) {
			d.ImageRepository = vectorImageRepository +
				"@sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0"
		},
		"repository carrying a tag behind a registry port": func(d *Document) {
			d.ImageRepository = "registry.lab.your-cloud.test:5000/lab-notes:1.0"
		},
		"repository without a registry": func(d *Document) { d.ImageRepository = "your-cloud/lab-notes" },
		"repository that is only a registry": func(d *Document) {
			d.ImageRepository = "registry.lab.your-cloud.test"
		},
		"empty repository":         func(d *Document) { d.ImageRepository = "" },
		"upper-case repository":    func(d *Document) { d.ImageRepository = "registry.lab.your-cloud.test/Lab-Notes" },
		"repository with a scheme": func(d *Document) { d.ImageRepository = "https://registry.lab.your-cloud.test/lab-notes" },
		"repository ending on a slash": func(d *Document) {
			d.ImageRepository = "registry.lab.your-cloud.test/lab-notes/"
		},
		"repository with an empty component": func(d *Document) {
			d.ImageRepository = "registry.lab.your-cloud.test//lab-notes"
		},
		"repository climbing": func(d *Document) {
			d.ImageRepository = "registry.lab.your-cloud.test/../lab-notes"
		},
		"repository above its bound": func(d *Document) {
			d.ImageRepository = "registry.lab.your-cloud.test/" + strings.Repeat("a", MaxImageRepositoryBytes)
		},

		"container port zero":         func(d *Document) { d.ContainerPort = 0 },
		"negative container port":     func(d *Document) { d.ContainerPort = -1 },
		"container port above range":  func(d *Document) { d.ContainerPort = MaxContainerPort + 1 },
		"container port beyond int16": func(d *Document) { d.ContainerPort = 70000 },

		"nine volumes": func(d *Document) { d.Volumes = numberedPaths("/srv/volume", MaxVolumes+1) },
		"nine tmpfs":   func(d *Document) { d.Tmpfs = numberedPaths("/run/scratch", MaxTmpfs+1) },
		"relative volume": func(d *Document) {
			d.Volumes = []string{"srv/notes"}
			d.Tmpfs = nil
		},
		"volume climbing out": func(d *Document) {
			d.Volumes = []string{"/srv/../../etc"}
			d.Tmpfs = nil
		},
		"volume carrying a single dot segment": func(d *Document) {
			d.Volumes = []string{"/srv/./notes"}
			d.Tmpfs = nil
		},
		"volume carrying a double separator": func(d *Document) {
			d.Volumes = []string{"/srv//notes"}
			d.Tmpfs = nil
		},
		"volume opening on a double separator": func(d *Document) {
			d.Volumes = []string{"//srv/notes"}
			d.Tmpfs = nil
		},
		"volume ending on a separator": func(d *Document) {
			d.Volumes = []string{"/srv/notes/"}
			d.Tmpfs = nil
		},
		"volume that is the root": func(d *Document) {
			d.Volumes = []string{"/"}
			d.Tmpfs = nil
		},
		"empty volume": func(d *Document) {
			d.Volumes = []string{""}
			d.Tmpfs = nil
		},
		"upper-case volume": func(d *Document) {
			d.Volumes = []string{"/srv/Notes"}
			d.Tmpfs = nil
		},
		"volume carrying a mount separator": func(d *Document) {
			d.Volumes = []string{"/srv/notes:ro"}
			d.Tmpfs = nil
		},
		"volume carrying a space": func(d *Document) {
			d.Volumes = []string{"/srv/lab notes"}
			d.Tmpfs = nil
		},
		"volume carrying a NUL": func(d *Document) {
			d.Volumes = []string{"/srv/notes\x00"}
			d.Tmpfs = nil
		},
		"volume above its byte bound": func(d *Document) {
			d.Volumes = []string{"/" + strings.Repeat("a", MaxContainerPathBytes)}
			d.Tmpfs = nil
		},
		"the same volume twice": func(d *Document) {
			d.Volumes = []string{vectorDataVolume, vectorDataVolume}
			d.Tmpfs = nil
		},
		"a volume inside another volume": func(d *Document) {
			d.Volumes = []string{"/srv", "/srv/data"}
			d.Tmpfs = nil
		},
		"a volume containing a tmpfs": func(d *Document) {
			d.Volumes = []string{"/srv"}
			d.Tmpfs = []string{"/srv/scratch"}
		},
		"a tmpfs containing a volume": func(d *Document) {
			d.Volumes = []string{"/srv/notes/scratch"}
			d.Tmpfs = []string{"/srv/notes"}
		},
		"a tmpfs equal to a volume": func(d *Document) {
			d.Volumes = []string{vectorDataVolume}
			d.Tmpfs = []string{vectorDataVolume}
		},
		"the same tmpfs twice": func(d *Document) {
			d.Volumes = nil
			d.Tmpfs = []string{vectorScratchTmpfs, vectorScratchTmpfs}
		},

		"thirty-three environment lines": func(d *Document) {
			d.Environment = numberedEnvironment(MaxEnvironmentLines + 1)
			d.SecretKeys = nil
		},
		"environment line without a separator": func(d *Document) {
			d.Environment = []string{"LAB_NOTES_TITLE"}
		},
		"lower-case environment key":         func(d *Document) { d.Environment = []string{"lab_notes_title=x"} },
		"environment key opening on a digit": func(d *Document) { d.Environment = []string{"1_TITLE=x"} },
		"environment key carrying a hyphen":  func(d *Document) { d.Environment = []string{"LAB-TITLE=x"} },
		"empty environment key":              func(d *Document) { d.Environment = []string{"=x"} },
		"environment key above its bound": func(d *Document) {
			d.Environment = []string{"A" + strings.Repeat("B", MaxEnvironmentKeyChars) + "=x"}
		},
		"the same environment key twice": func(d *Document) {
			d.Environment = []string{"LAB_NOTES_TITLE=one", "LAB_NOTES_TITLE=two"}
		},
		"a key that is an environment line and a secret at once": func(d *Document) {
			d.SecretKeys = []string{"LAB_NOTES_TITLE"}
		},
		"environment value above its bound": func(d *Document) {
			d.Environment = []string{"LONG=" + strings.Repeat("x", MaxEnvironmentValueBytes+1)}
		},
		"environment value carrying a tab":   func(d *Document) { d.Environment = []string{"TITLE=a\tb"} },
		"environment value carrying a break": func(d *Document) { d.Environment = []string{"TITLE=a\nb"} },
		"environment value carrying a NUL":   func(d *Document) { d.Environment = []string{"TITLE=a\x00b"} },
		"environment value outside ASCII":    func(d *Document) { d.Environment = []string{"TITLE=café"} },
		"environment value carrying DEL":     func(d *Document) { d.Environment = []string{"TITLE=a\x7fb"} },
		"a truncated placeholder": func(d *Document) {
			d.Environment = []string{"ORIGIN=https://{origin_hos}/"}
		},
		"an unterminated placeholder": func(d *Document) {
			d.Environment = []string{"ORIGIN=https://{origin_host"}
		},
		"an upper-case placeholder": func(d *Document) {
			d.Environment = []string{"ORIGIN=https://{ORIGIN_HOST}/"}
		},
		"another placeholder name": func(d *Document) {
			d.Environment = []string{"ORIGIN=https://{machine_id}/"}
		},
		"an opening brace on its own": func(d *Document) { d.Environment = []string{"ORIGIN=a{b"} },
		"a closing brace on its own":  func(d *Document) { d.Environment = []string{"ORIGIN=a}b"} },
		"a brace pair around nothing": func(d *Document) { d.Environment = []string{"ORIGIN={}"} },
		"a nested placeholder": func(d *Document) {
			d.Environment = []string{"ORIGIN={{origin_host}}"}
		},

		"seventeen secret keys": func(d *Document) {
			d.Environment = nil
			d.SecretKeys = numberedKeys("SECRET", MaxSecretKeys+1)
		},
		"lower-case secret key":               func(d *Document) { d.SecretKeys = []string{"lab_notes_token"} },
		"secret key carrying a separator":     func(d *Document) { d.SecretKeys = []string{"LAB_NOTES_TOKEN=x"} },
		"empty secret key":                    func(d *Document) { d.SecretKeys = []string{""} },
		"secret key opening on an underscore": func(d *Document) { d.SecretKeys = []string{"_TOKEN"} },
		"the same secret key twice": func(d *Document) {
			d.SecretKeys = []string{vectorSecretKey, vectorSecretKey}
		},
	} {
		document := vectorReference()
		mutate(&document)
		if _, err := Decode(hostileDefinitionDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestTheFourReservedSlugsAreRefusedByName keeps one name designating exactly
// one door.
//
// The archive operations name a service by its service_profile field, and the
// third door shares that namespace with the profiles the product delivers. A
// definition that could take one of those four names would make a lookup succeed
// on both sides, and the ambiguity would then have to be resolved by a
// comparison someone remembered to write.
func TestTheFourReservedSlugsAreRefusedByName(t *testing.T) {
	t.Parallel()
	for _, slug := range []string{"bentopdf", "vaultwarden", "probe", "entrypoint"} {
		document := vectorReference()
		document.Slug = slug
		if _, err := Decode(hostileDefinitionDocument(t, document)); err == nil {
			t.Fatalf("the reserved slug %q was accepted", slug)
		}
	}

	// The reservation is on the exact names and on nothing around them: a slug
	// that merely contains one of them is a slug like any other, because what the
	// two namespaces compare is equality.
	for _, slug := range []string{"bentopdf2", "my-vaultwarden", "probes", "entrypoints"} {
		document := vectorReference()
		document.Slug = slug
		if _, err := Decode(hostileDefinitionDocument(t, document)); err != nil {
			t.Fatalf("the slug %q was refused: %v", slug, err)
		}
	}
}

// TestDecodeRefusesEveryDocumentTheStrictDecodingRefuses is the surface no field
// bound can cover: what is refused before any value of the document is read.
func TestDecodeRefusesEveryDocumentTheStrictDecodingRefuses(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"an unknown field": strings.Replace(vectorReferenceDocument,
			`{"schema_version":1,`, `{"host_path":"/etc/shadow","schema_version":1,`, 1),
		"a field of a plan": strings.Replace(vectorReferenceDocument,
			`{"schema_version":1,`, `{"image_digest":"sha256:00","schema_version":1,`, 1),
		"a repeated field": strings.Replace(vectorReferenceDocument,
			`{"schema_version":1,`, `{"slug":"other","schema_version":1,`, 1),
		"a field in another case": strings.Replace(vectorReferenceDocument,
			`"slug":`, `"Slug":`, 1),
		"two documents in one":     vectorReferenceDocument + vectorMinimalDocument,
		"trailing bytes":           vectorReferenceDocument + " ]",
		"an array of definitions":  "[" + vectorReferenceDocument + "]",
		"an empty document":        "",
		"a bare null":              "null",
		"a truncated document":     vectorReferenceDocument[:len(vectorReferenceDocument)-1],
		"a string where a list is": strings.Replace(vectorReferenceDocument, `"tmpfs":["/tmp"]`, `"tmpfs":"/tmp"`, 1),
		"a string where the port is": strings.Replace(vectorReferenceDocument,
			`"container_port":8080`, `"container_port":"8080"`, 1),
		"a fractional port": strings.Replace(vectorReferenceDocument,
			`"container_port":8080`, `"container_port":8080.5`, 1),
	} {
		if _, err := Decode([]byte(document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestADefinitionIsRefusedBeforeItIsParsedWhenItIsTooLarge is the bound that
// exists so that no cost of parsing depends on what a document claims.
//
// The subject is a definition every field of which is inside its own bound and
// whose whole is not: thirty-two lines of five hundred and twelve bytes fit the
// cardinal and the value bounds and do not fit the document. It is refused by
// the byte bound at both ends — the Controller will not render it, and no decoder
// will read it.
func TestADefinitionIsRefusedBeforeItIsParsedWhenItIsTooLarge(t *testing.T) {
	t.Parallel()
	document := vectorMinimal()
	for _, key := range numberedKeys("LINE", MaxEnvironmentLines) {
		document.Environment = append(document.Environment,
			key+"="+strings.Repeat("x", MaxEnvironmentValueBytes))
	}
	if err := document.Validate(); err != nil {
		t.Fatalf("every field of the subject must be inside its own bound: %v", err)
	}

	oversized := hostileDefinitionDocument(t, document)
	if len(oversized) <= MaxDefinitionBytes {
		t.Fatalf("the subject of this test must exceed the bound, and it is %d bytes", len(oversized))
	}
	if _, err := Decode(oversized); err == nil {
		t.Fatal("a definition beyond the byte bound was decoded")
	}
	if _, err := document.Encode(); err == nil {
		t.Fatal("a definition beyond the byte bound was rendered")
	}

	// A transcript and a digest are still computable, because they are taken over
	// the fields rather than over a rendering. Nothing transports them: what
	// cannot be encoded cannot be frozen.
	if _, err := document.SHA256(); err != nil {
		t.Fatalf("the digest of a valid but unrenderable definition: %v", err)
	}
}
