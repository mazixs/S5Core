// Command stealthcheck runs the stealth checklist over a corpus of first
// packets and prints the result.
//
// A corpus is a directory of files, one per connection, each holding the raw
// bytes the connection put on the wire first. Two ways to get one:
//
//	# from the product itself, 1000 connections through the obfs layer:
//	S5CORE_STEALTH_CORPUS=/tmp/corpus go test ./pkg/obfs/ -run TestTheStealthChecklist
//
//	# from a capture, one file per stream (tshark, one payload per line):
//	tshark -r capture.pcap -Y 'tcp.port==27015 && tcp.len>0' \
//	  -T fields -e tcp.stream -e tcp.payload | sort -u -k1,1 | \
//	  while read -r s hex; do printf '%s' "$hex" | xxd -r -p > /tmp/corpus/$s.bin; done
//
// The exit status is 1 when the corpus fails the gate given by -max-blocked,
// so the tool can sit in a pipeline. Level 1 answers "would a fully-encrypted
// traffic policy block this"; level 2 answers "does the protocol leak its own
// structure across connections". Neither answers "is this undetectable".
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/mazixs/S5Core/internal/stealth"
)

func main() {
	prefix := flag.Int("prefix", 64, "how many leading bytes of each stream the positional check looks at")
	maxBlocked := flag.Float64("max-blocked", 1.0, "fail if a larger share of streams matches no level-1 exemption")
	limit := flag.Int("limit", 0, "read at most this many streams (0 = all)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <corpus directory>\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(2)
	}

	corpus, err := readCorpus(flag.Arg(0), *limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(corpus) == 0 {
		fmt.Fprintf(os.Stderr, "no files in %s\n", flag.Arg(0))
		os.Exit(2)
	}

	report := stealth.Analyze(corpus, *prefix)
	fmt.Print(report)

	if share := report.Level1.BlockedShare(); share > *maxBlocked {
		fmt.Fprintf(os.Stderr, "\nFAIL: %.1f%% of streams match no exemption, limit is %.1f%%\n",
			share*100, *maxBlocked*100)
		os.Exit(1)
	}
}

func readCorpus(dir string, limit int) ([][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	// Sorted, so two runs over the same directory report the same thing.
	sort.Strings(names)
	if limit > 0 && len(names) > limit {
		names = names[:limit]
	}

	corpus := make([][]byte, 0, len(names))
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			continue
		}
		corpus = append(corpus, b)
	}
	return corpus, nil
}
