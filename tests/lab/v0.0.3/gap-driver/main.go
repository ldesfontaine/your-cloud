package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/buffer"
	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/observation"
)

func main() {
	stateDirectory := flag.String("state-dir", "", "absolute private Daemon state directory")
	machineID := flag.String("machine-id", "", "enrolled LAB machine identifier")
	flag.Parse()
	if flag.NArg() != 0 || *stateDirectory == "" || machineid.Validate(*machineID) != nil {
		log.Fatal("usage: gap-driver --state-dir ABSOLUTE --machine-id ID")
	}
	local, err := buffer.Open(*stateDirectory, buffer.Limits{
		MaxBytes: 16 * 1024, MaxRecords: 2, MaxAge: time.Hour,
	})
	if err != nil {
		log.Fatalf("open bounded Daemon buffer: %v", err)
	}
	before, err := local.Stats()
	if err != nil || before.PendingRecords != 0 {
		log.Fatalf("Daemon buffer must be drained before the accelerated pressure proof: %#v %v", before, err)
	}
	sources := observation.SystemSources()
	now := time.Now().UTC()
	for index := 0; index < 3; index++ {
		health := observation.CollectHostHealth(sources)
		if _, err := local.Enqueue(*machineID, health, now.Add(time.Duration(index)*time.Nanosecond)); err != nil {
			log.Fatalf("enqueue real host observation %d: %v", index+1, err)
		}
	}
	after, err := local.Stats()
	if err != nil {
		log.Fatalf("inspect pressured Daemon buffer: %v", err)
	}
	if after.PendingRecords != 2 || after.GapCount != 1 || after.NextSequence != before.NextSequence+3 {
		log.Fatalf("accelerated pressure did not create the exact one-record gap: before=%#v after=%#v", before, after)
	}
	fmt.Fprintf(os.Stdout, "before_next=%d after_next=%d pending=%d gaps=%d\n",
		before.NextSequence, after.NextSequence, after.PendingRecords, after.GapCount)
}
