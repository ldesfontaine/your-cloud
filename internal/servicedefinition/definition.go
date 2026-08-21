// Package servicedefinition gives the third door of the product its one
// document: the definition a user writes for a service the product does not
// know.
//
// A definition is inert. Validating, canonising and hashing one creates no
// account, no directory, no unit and no plan, and this package contacts nothing:
// it turns bytes into a bounded value, one canonical spelling and one digest.
// Every effect continues to be born of a plan a human approved, and a plan only
// ever pins a definition by that digest.
//
// Nothing here depends on the plan schemas, and nothing here is a plan. The two
// documents share their procedures — one bounded strict JSON document, one
// domain-separated binary transcript, one SHA-256 over the transcript rather
// than over the received bytes — and they share no field, no bound and no
// domain, so neither can ever grow because the other did.
//
// The transcript below is the counterpart of the one written on the App
// side. The two are held against one another by deterministic vectors on both
// sides rather than by reading, because a canonical encoding that exists in two
// implementations is only canonical while the two agree byte for byte.
//
// The layout is:
//
//	domain  "your-cloud/service-definition.v1\0"
//	then    schema_version                 on 1 byte
//	        slug, image_repository         as uint32 length-prefixed fields
//	        container_port                 as a uint32 big-endian
//	then the four lists, always all four and always in this order:
//	        volumes, tmpfs, environment, secret_keys
//	        each one a uint32 big-endian count, followed by exactly that many
//	        uint32 length-prefixed fields, in the order the document declares
//
// A count-prefixed sequence is what makes a list unambiguous without a
// separator: nothing inside an element can be read as the end of it, because the
// reader knows how many fields follow before it reads any, and each of those
// fields announces its own length. Every list is written even when it is empty —
// as a count of zero — so the four counts are always at determined offsets and
// no document can be read as another with one list shifted into the next.
//
// An environment line travels whole rather than split into a key and a value.
// The key grammar excludes the separator, so splitting a line at its first `=`
// is a function of the line and nothing is lost by hashing the line itself — and
// one field instead of two is one fewer place for the two implementations to
// disagree.
//
// The order of a list is the order the document declares, and the digest covers
// it. Two definitions that differ only by the order of a list are two documents
// and two digests, exactly as two definitions differing by a value are: this
// package freezes what its author wrote rather than a reordering of it, so that
// re-reading a frozen definition returns the bytes that were frozen.
package servicedefinition

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	// SchemaVersion is the one definition version this palier reads and writes.
	SchemaVersion = 1

	// TranscriptDomain separates a definition digest from every plan transcript
	// of the product and from every other transcript of it. Its terminating NUL
	// cannot appear in any textual field, so no prefix of one transcript is a
	// prefix of another.
	TranscriptDomain = "your-cloud/service-definition.v1\x00"

	// MaxDefinitionBytes bounds a definition before it is parsed.
	//
	// It is the bound of the contract and it is its own: a definition carries
	// lists no plan has ever carried, and this is twice the plan bound while
	// staying small enough for the App to always display the whole document.
	// The two bounds are separate so that neither document grows one day because
	// the other did.
	MaxDefinitionBytes = 8192

	// MaxSlugChars is the whole reason the slug is narrower than the archive slot
	// whose grammar it borrows. The derived account is your-cloud-user-<slug> and
	// must fit the thirty-two characters a user name of the machine has; the
	// prefix consumes exactly sixteen of them, and the derivation never
	// truncates — so two distinct slugs are two distinct accounts by
	// construction rather than by vigilance.
	MaxSlugChars = 16

	// MaxImageRepositoryBytes bounds the repository a definition names. It is the
	// bound a repository name has in the distribution specification, applied here
	// so that the field is bounded on its own rather than only by the document.
	MaxImageRepositoryBytes = 255

	// MinContainerPort and MaxContainerPort bound the port the image listens on
	// inside its own namespace. The range opens at 1 and not at 1024: a container
	// port is not a port of the host, and the privilege a low one used to require
	// is a sysctl the placement derives from this very field.
	MinContainerPort = 1
	MaxContainerPort = 65535

	// MaxVolumes and MaxTmpfs bound how many container paths one definition
	// declares, on each of the two lists.
	MaxVolumes = 8
	MaxTmpfs   = 8

	// MaxContainerPathBytes bounds one declared container path.
	MaxContainerPathBytes = 253

	// MaxEnvironmentLines and MaxSecretKeys bound the inert configuration and the
	// names of the values the machine will generate.
	MaxEnvironmentLines = 32
	MaxSecretKeys       = 16

	// MaxEnvironmentKeyChars and MaxEnvironmentValueBytes bound the two halves of
	// an environment line.
	MaxEnvironmentKeyChars   = 64
	MaxEnvironmentValueBytes = 512

	// OriginHostPlaceholder is the one interpolation a definition may carry, and
	// the one sequence in which a brace may appear in a value. There is no other
	// template and no escape: a brace anywhere else is a named refusal rather
	// than a syntax a later palier would have to keep accepting.
	OriginHostPlaceholder = "{origin_host}"
)

var (
	// canonicalSlug is the grammar of snapshot_slot narrowed to sixteen
	// characters: lower-case letters, digits and hyphens, opening on a letter or
	// a digit. There is no dot and no separator inside those bounds, so a slug is
	// always exactly one name and never a path something derived from it could
	// climb out of.
	canonicalSlug = regexp.MustCompile(fmt.Sprintf(`^[a-z0-9][a-z0-9-]{0,%d}$`, MaxSlugChars-1))

	// canonicalRegistryHost is the part of a repository that names where the
	// images come from: a lower-case host, optionally carrying the port of a
	// registry that does not listen on the usual one.
	canonicalRegistryHost = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?$`)

	// canonicalRepositoryPath is what follows the registry: one or more
	// lower-case components of the distribution specification's own grammar. It
	// admits neither a tag nor a digest, and it admits no upper case, which is
	// what keeps one repository from having two spellings.
	canonicalRepositoryPath = regexp.MustCompile(
		`^[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*$`)

	// canonicalPathSegment is one segment of a container path: lower-case
	// letters, digits, dots, underscores and hyphens. The closed set excludes the
	// colon that separates a mount specification, with no escape existing
	// anywhere, and it excludes every spelling of a separator a path could climb
	// with. Whether a segment made only of dots is one this package accepts is
	// decided beside this expression, which cannot state it.
	canonicalPathSegment = regexp.MustCompile(`^[a-z0-9._-]+$`)

	// canonicalEnvironmentKey is the grammar of both an environment key and a
	// secret key. They are one grammar because they are one namespace: the two
	// lists are required to be disjoint, and a name that could be spelled in one
	// and not in the other would make that requirement depend on which list it
	// was written in.
	canonicalEnvironmentKey = regexp.MustCompile(
		fmt.Sprintf(`^[A-Z][A-Z0-9_]{0,%d}$`, MaxEnvironmentKeyChars-1))

	// reservedSlugs are the four names a definition may not take.
	//
	// The reason is stronger than a collision of names: an archive operation
	// names a service by its service_profile field, and the third door shares
	// that namespace with the profiles the product delivers. Reserving the four
	// names at the source is what makes one name designate exactly one door — a
	// lookup that succeeds on one side only, rather than a comparison someone has
	// to remember to write.
	//
	// They are spelled here rather than imported, because a definition is not a
	// plan and this package depends on no plan schema. Holding the two lists
	// against one another belongs where both are already in scope: the Controller
	// that serves the two doors.
	reservedSlugs = map[string]struct{}{
		"bentopdf":    {},
		"vaultwarden": {},
		"probe":       {},
		"entrypoint":  {},
	}
)

// Document is one definition of a user service. The declaration order below is
// the canonical encoding order and the transcript order at once, and no field of
// a definition lives outside it.
//
// Everything the machine owns is absent on purpose. A definition names no
// account, no host path, no home, no egress table and no secret value: all of
// those are derived from the slug by the machine that acts, and no field here
// can move any of them.
type Document struct {
	SchemaVersion   int      `json:"schema_version"`
	Slug            string   `json:"slug"`
	ImageRepository string   `json:"image_repository"`
	ContainerPort   int      `json:"container_port"`
	Volumes         []string `json:"volumes"`
	Tmpfs           []string `json:"tmpfs"`
	Environment     []string `json:"environment"`
	SecretKeys      []string `json:"secret_keys"`
}

// Decode accepts one bounded, strict, fully validated definition.
//
// It never returns a partially checked definition: a caller that holds one may
// assume every field is inside the bounds of the contract, that the fields it
// holds are exactly the ones the schema declares, and that the two lists of
// container paths do not overlap.
func Decode(document []byte) (Document, error) {
	if len(document) == 0 || len(document) > MaxDefinitionBytes {
		return Document{}, fmt.Errorf("service definition must contain 1..%d bytes", MaxDefinitionBytes)
	}
	var parsed Document
	if err := strictjson.Decode(document, &parsed); err != nil {
		return Document{}, fmt.Errorf("decode service definition: %w", err)
	}
	if err := parsed.Validate(); err != nil {
		return Document{}, err
	}
	return parsed, nil
}

// Validate holds a definition against the whole contract of the palier.
//
// It reads from the top down as the contract does: the version, the name, where
// the images come from, the port the image listens on, then the two lists of
// paths held against one another, then the two lists of keys held against one
// another. Nothing here looks at a machine, and nothing here has an effect.
func (document Document) Validate() error {
	if document.SchemaVersion != SchemaVersion {
		return errors.New("service definition schema version is unsupported")
	}
	if err := ValidateSlug(document.Slug); err != nil {
		return err
	}
	if err := ValidateImageRepository(document.ImageRepository); err != nil {
		return err
	}
	if document.ContainerPort < MinContainerPort || document.ContainerPort > MaxContainerPort {
		return fmt.Errorf("service definition container_port must be within %d..%d",
			MinContainerPort, MaxContainerPort)
	}
	if err := validateMounts(document.Volumes, document.Tmpfs); err != nil {
		return err
	}
	return validateEnvironment(document.Environment, document.SecretKeys)
}

// Encode renders the one canonical encoding of a definition for transport.
//
// A transport may reindent what it carries without changing the definition — the
// digest is rebuilt from the fields, not from the bytes — but the Controller
// emits exactly one spelling, so that the document a human is shown, the
// document an Auxiliary receives and the document a digest was taken over are
// the same bytes rather than three encodings that happen to agree.
//
// The four lists are always rendered, an empty one as an empty array. A
// definition that declared none of them, one that declared them empty and one
// that spelled them null are the same definition, and this is the one spelling
// they all freeze to.
func (document Document) Encode() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document.withExplicitLists()); err != nil {
		return nil, fmt.Errorf("encode service definition: %w", err)
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	// The bound is required again after the rendering rather than trusted from
	// the fields: a definition that validates and still does not fit is refused
	// rather than transported.
	if len(encoded) == 0 || len(encoded) > MaxDefinitionBytes {
		return nil, fmt.Errorf("service definition must contain 1..%d bytes", MaxDefinitionBytes)
	}
	return encoded, nil
}

// Transcript rebuilds the exact bytes a definition digest is taken over, in the
// layout documented at the head of this file.
//
// It is built from the parsed fields and never from a received document, so two
// implementations that read the same definition produce the same digest, a
// transport that reshapes the JSON transports the same definition, and a
// transport that changes one value transports a definition whose digest no
// longer matches the plan that pinned it.
func (document Document) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	transcript := make([]byte, 0, len(TranscriptDomain)+MaxDefinitionBytes/8)
	transcript = append(transcript, TranscriptDomain...)
	transcript = append(transcript, byte(document.SchemaVersion))
	transcript = appendField(transcript, []byte(document.Slug))
	transcript = appendField(transcript, []byte(document.ImageRepository))
	transcript = appendUint32(transcript, uint32(document.ContainerPort))
	transcript = appendList(transcript, document.Volumes)
	transcript = appendList(transcript, document.Tmpfs)
	transcript = appendList(transcript, document.Environment)
	return appendList(transcript, document.SecretKeys), nil
}

// SHA256 is the lower-case hexadecimal value a plan names as
// definition_digest, in the exact spelling that field requires.
func (document Document) SHA256() (string, error) {
	transcript, err := document.Transcript()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(transcript)
	return hex.EncodeToString(digest[:]), nil
}

// InterpolatesOriginHost reports whether this definition consumes the origin a
// plan approves.
//
// It is the one reading of the placeholder anything outside this package
// performs, and it exists so that the template stays spelled in exactly one
// place. A plan of a user service carries origin_host precisely when this answers
// true — a definition that names the origin makes it a value the container
// receives, and a definition that does not would turn an approved name into an
// intention without a consequence. That rule is a cross-check between a plan and
// the definition it pins, held by the Controller at construction and re-held by
// the Auxiliary with the definition in hand; both ask this question rather than
// searching for the sequence themselves.
//
// Scanning the whole line is exact rather than approximate: a key is upper-case
// letters, digits and underscores, so a brace can only ever appear in the value,
// and validation has already refused every brace that is not the placeholder
// itself. A definition this package has not validated is outside the contract and
// answers nothing meaningful here, as everywhere else.
func (document Document) InterpolatesOriginHost() bool {
	for _, line := range document.Environment {
		if strings.Contains(line, OriginHostPlaceholder) {
			return true
		}
	}
	return false
}

// withExplicitLists is the one place a list that was never declared becomes an
// empty one, so that the canonical spelling of a definition does not depend on
// how its author left a list out.
func (document Document) withExplicitLists() Document {
	document.Volumes = orEmpty(document.Volumes)
	document.Tmpfs = orEmpty(document.Tmpfs)
	document.Environment = orEmpty(document.Environment)
	document.SecretKeys = orEmpty(document.SecretKeys)
	return document
}

func orEmpty(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// ValidateSlug bounds the one name everything else about the service derives
// from, and refuses the four names another door already answers to.
//
// It is exported because the plan schema needs to state the same rule and must
// not own a second spelling of it: a plan names a definition by its slug in
// definition_slug, and an archive operation names one in service_profile beside
// the closed list of delivered profiles. A second expression that agreed with
// this one today would be a second expression to keep agreeing with it, and the
// two would disagree on exactly the day the reserved names changed.
func ValidateSlug(slug string) error {
	if !canonicalSlug.MatchString(slug) {
		return fmt.Errorf(
			"service definition slug must be 1..%d lower-case letters, digits and hyphens opening on a letter or a digit",
			MaxSlugChars)
	}
	if _, reserved := reservedSlugs[slug]; reserved {
		return fmt.Errorf("service definition slug %q is reserved by a door of the product", slug)
	}
	return nil
}

// ValidateImageRepository requires where the images come from, and refuses to be
// told which one.
//
// It is exported for the reason ValidateSlug is: the image_reference of a user
// service plan must be exactly the repository of the definition it pins, so the
// plan schema bounds that field by this very rule rather than by a second one
// that would have to keep agreeing with it.
//
// The tag and the digest are refused by their own names before the grammar is
// read, so that the most likely mistake a human makes — pasting the reference
// they pull with — is answered by the sentence that explains the rule rather
// than by a generic malformation. The digest of an instance lives in the plan
// that deploys it, and updating a service is a new plan whose digest differs,
// never a silent mutation of what a definition names.
func ValidateImageRepository(repository string) error {
	if repository == "" || len(repository) > MaxImageRepositoryBytes {
		return fmt.Errorf("service definition image_repository must contain 1..%d bytes",
			MaxImageRepositoryBytes)
	}
	if strings.Contains(repository, "@") {
		return errors.New(
			"service definition image_repository names a repository, never a digest: the digest of an instance belongs to the plan that deploys it")
	}
	if strings.Contains(repository[strings.LastIndex(repository, "/")+1:], ":") {
		return errors.New(
			"service definition image_repository names a repository, never a tag: a tag is an identity nowhere in this product")
	}
	registry, path, qualified := strings.Cut(repository, "/")
	if !qualified {
		return errors.New(
			"service definition image_repository must name the registry the images come from")
	}
	// A first component that carries neither a dot nor a port is a name, not a
	// registry: what it resolves to would be decided by the search list of
	// whatever daemon pulls it, which is a second and movable truth beside the
	// digest the plan pins.
	if !strings.ContainsAny(registry, ".:") || !canonicalRegistryHost.MatchString(registry) {
		return fmt.Errorf(
			"service definition image_repository must open on a registry host, and %q is not one", registry)
	}
	if !canonicalRepositoryPath.MatchString(path) {
		return fmt.Errorf(
			"service definition image_repository path %q must be lower-case components of letters, digits, dots, underscores and hyphens",
			path)
	}
	return nil
}

// mount is one declared container path, kept beside the list it came from and
// beside the segments it splits into.
//
// The segments are carried rather than recomputed because the overlap rule is
// stated on them: two paths overlap when one is the other or opens it segment by
// segment, and comparing the strings instead would make /srv and /srvdata a
// collision while missing nothing real.
type mount struct {
	field    string
	path     string
	segments []string
}

// validateMounts holds the two lists of container paths, then holds them
// against one another as one list.
//
// The union is what the contract bounds, and it has to be: two mounts that
// overlap would be two writes whose order decides the result, and the order is
// not a field. The refusal names both entries, because either of them could be
// the one its author meant to keep.
func validateMounts(volumes, tmpfs []string) error {
	if len(volumes) > MaxVolumes {
		return fmt.Errorf("service definition volumes must hold 0..%d entries", MaxVolumes)
	}
	if len(tmpfs) > MaxTmpfs {
		return fmt.Errorf("service definition tmpfs must hold 0..%d entries", MaxTmpfs)
	}

	declared := make([]mount, 0, len(volumes)+len(tmpfs))
	for _, list := range []struct {
		field   string
		entries []string
	}{{"volumes", volumes}, {"tmpfs", tmpfs}} {
		for _, path := range list.entries {
			segments, err := validateContainerPath(list.field, path)
			if err != nil {
				return err
			}
			declared = append(declared, mount{field: list.field, path: path, segments: segments})
		}
	}

	for index, entry := range declared {
		for _, other := range declared[index+1:] {
			if !opensOrEquals(entry.segments, other.segments) && !opensOrEquals(other.segments, entry.segments) {
				continue
			}
			return fmt.Errorf("service definition %s %q and %s %q are the same mount or one inside the other",
				entry.field, entry.path, other.field, other.path)
		}
	}
	return nil
}

// validateContainerPath bounds one path inside the container, and returns the
// segments the overlap rule is stated on.
//
// Absolute, normalised and lower-case is the whole of it. A path that is not
// normalised has a second spelling, and a second spelling of a mount is a second
// digest for the same state; a path that climbs, or that is the root itself,
// names something the definition has no business naming.
func validateContainerPath(field, path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("service definition %s %q must be an absolute container path", field, path)
	}
	if path == "/" {
		return nil, fmt.Errorf("service definition %s must not be the root of the container alone", field)
	}
	if len(path) > MaxContainerPathBytes {
		return nil, fmt.Errorf("service definition %s %q must contain at most %d bytes",
			field, path, MaxContainerPathBytes)
	}
	if strings.HasSuffix(path, "/") {
		return nil, fmt.Errorf("service definition %s %q must not end on a separator", field, path)
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("service definition %s %q must not carry an empty segment", field, path)
		}
		if segment == "." || segment == ".." {
			return nil, fmt.Errorf("service definition %s %q must not carry a relative segment", field, path)
		}
		if !canonicalPathSegment.MatchString(segment) {
			return nil, fmt.Errorf(
				"service definition %s %q must carry only lower-case letters, digits, dots, underscores and hyphens",
				field, path)
		}
	}
	return segments, nil
}

// opensOrEquals reports whether the first path is the second or contains it,
// segment by segment. Comparing segments rather than strings is what keeps
// /srv/data out of /srv while leaving /srvdata beside /srv where it belongs.
func opensOrEquals(outer, inner []string) bool {
	if len(outer) > len(inner) {
		return false
	}
	for index, segment := range outer {
		if inner[index] != segment {
			return false
		}
	}
	return true
}

// validateEnvironment holds the inert configuration and the names of the
// generated secrets, and holds the two against one another.
//
// They are validated together because the rule that matters is shared: one key
// is one name in one namespace. A key declared twice would let the order of the
// list decide which value the container receives, and a key that is at once an
// environment line and a secret would be a value displayed everywhere the
// definition is displayed and a value the machine generates and never shows —
// the two cannot be the same name.
func validateEnvironment(environment, secretKeys []string) error {
	if len(environment) > MaxEnvironmentLines {
		return fmt.Errorf("service definition environment must hold 0..%d lines", MaxEnvironmentLines)
	}
	if len(secretKeys) > MaxSecretKeys {
		return fmt.Errorf("service definition secret_keys must hold 0..%d keys", MaxSecretKeys)
	}

	declared := make(map[string]string, len(environment)+len(secretKeys))
	for _, line := range environment {
		key, value, separated := strings.Cut(line, "=")
		if !separated {
			return fmt.Errorf("service definition environment line %q must be spelled KEY=value", line)
		}
		if err := validateEnvironmentKey("environment", key); err != nil {
			return err
		}
		if err := validateEnvironmentValue(key, value); err != nil {
			return err
		}
		if err := claimKey(declared, "environment", key); err != nil {
			return err
		}
	}
	for _, key := range secretKeys {
		if err := validateEnvironmentKey("secret_keys", key); err != nil {
			return err
		}
		if err := claimKey(declared, "secret_keys", key); err != nil {
			return err
		}
	}
	return nil
}

// claimKey takes one name in the one namespace the two lists share, and names
// which of the two refusals a taken name is: the same list twice, or the two
// lists at once.
func claimKey(declared map[string]string, field, key string) error {
	previous, taken := declared[key]
	if !taken {
		declared[key] = field
		return nil
	}
	if previous == field {
		return fmt.Errorf("service definition %s declares the key %q twice", field, key)
	}
	return fmt.Errorf(
		"service definition declares %q as an environment key and as a secret key at once", key)
}

func validateEnvironmentKey(field, key string) error {
	if !canonicalEnvironmentKey.MatchString(key) {
		return fmt.Errorf(
			"service definition %s key %q must be 1..%d upper-case letters, digits and underscores opening on a letter",
			field, key, MaxEnvironmentKeyChars)
	}
	return nil
}

// validateEnvironmentValue bounds one inert value and the one interpolation the
// product has.
//
// The scan walks the value rather than searching it, so that the rule holds in
// one direction only: a brace is accepted exactly when it opens the whole
// sequence, and everything else — a truncated placeholder, an unknown name
// between braces, a closing brace on its own — is refused at the byte where it
// stops being the sequence. There is no escape to reach past it, which is what
// keeps a value from ever becoming a template a later palier has to keep
// evaluating.
func validateEnvironmentValue(key, value string) error {
	if len(value) > MaxEnvironmentValueBytes {
		return fmt.Errorf("service definition environment value of %q must contain at most %d bytes",
			key, MaxEnvironmentValueBytes)
	}
	for index := 0; index < len(value); {
		character := value[index]
		if character < 0x20 || character > 0x7e {
			return fmt.Errorf("service definition environment value of %q must be printable ASCII", key)
		}
		switch character {
		case '{':
			if !strings.HasPrefix(value[index:], OriginHostPlaceholder) {
				return fmt.Errorf(
					"service definition environment value of %q may carry a brace only inside %s",
					key, OriginHostPlaceholder)
			}
			index += len(OriginHostPlaceholder)
		case '}':
			return fmt.Errorf(
				"service definition environment value of %q carries a closing brace outside %s",
				key, OriginHostPlaceholder)
		default:
			index++
		}
	}
	return nil
}

// appendList writes one list as the count of its elements followed by the
// elements themselves, which is what makes the four lists readable in sequence
// without a separator any element could contain.
func appendList(buffer []byte, entries []string) []byte {
	buffer = appendUint32(buffer, uint32(len(entries)))
	for _, entry := range entries {
		buffer = appendField(buffer, []byte(entry))
	}
	return buffer
}

func appendField(buffer []byte, value []byte) []byte {
	buffer = appendUint32(buffer, uint32(len(value)))
	return append(buffer, value...)
}

func appendUint32(buffer []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(buffer, encoded[:]...)
}
