package auxiliary

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTheNextSubordinateRangeNeverOverlapsWhatTheMachineAlreadyNames holds the
// allocation to the property that matters: the files are the authority, and a
// new range starts strictly above every range they already name, whoever wrote
// it there and in whichever of the two files it lives.
func TestTheNextSubordinateRangeNeverOverlapsWhatTheMachineAlreadyNames(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		subuid string
		subgid string
		want   uint64
	}{
		{
			name: "empty files start at the floor",
			want: subordinateRangeFloor,
		},
		{
			name:   "an ordinary user's range is stepped over",
			subuid: "debian:100000:65536\n",
			subgid: "debian:100000:65536\n",
			want:   165536,
		},
		{
			name:   "the highest range wins regardless of the file it lives in",
			subuid: "debian:100000:65536\n",
			subgid: "operator:400000:65536\n",
			want:   465536,
		},
		{
			name:   "malformed and comment lines are not ranges",
			subuid: "# comment\nbroken:line\ndebian:100000:65536\n",
			want:   165536,
		},
		{
			name:   "a hand-written range below the floor does not lower the start",
			subuid: "legacy:1000:100\n",
			want:   subordinateRangeFloor,
		},
	}

	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			subuidPath := filepath.Join(directory, "subuid")
			subgidPath := filepath.Join(directory, "subgid")
			if err := os.WriteFile(subuidPath, []byte(current.subuid), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(subgidPath, []byte(current.subgid), 0o644); err != nil {
				t.Fatal(err)
			}
			start, err := nextSubordinateRangeStart(subuidPath, subgidPath)
			if err != nil {
				t.Fatal(err)
			}
			if start != current.want {
				t.Fatalf("allocation starts at %d, wanted %d", start, current.want)
			}
		})
	}

	// A file that does not exist is a machine that never allocated: the floor,
	// not an error — the files appear with the first allocation.
	start, err := nextSubordinateRangeStart(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatal(err)
	}
	if start != subordinateRangeFloor {
		t.Fatalf("an absent file starts allocation at %d, wanted the floor", start)
	}
}
