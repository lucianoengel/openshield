// Command openshield-dlp-index is the operator tool for DLP-3 exact-data/document indexes (ADR-9).
//
// It builds a k-anonymized detection index (EDM single-value, multi-cell record, or IDM
// document-fingerprint) from operator input and SIGNS it with an operator Ed25519 key, producing
// the exact bytes openshield-worker verifies (OPENSHIELD_DLP_INDEX_PUBKEY) before loading it into the
// sandbox. The index holds only hashes — never the raw sensitive data — so it is safe to distribute;
// the signature ensures a compromised distribution path cannot inject or poison it (T2/D14).
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucianoengel/openshield/internal/classify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "build":
		build(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `openshield-dlp-index — build + sign DLP-3 detection indexes (ADR-9)

  keygen --out-key operator.key --out-pub operator.pub
      Generate a raw Ed25519 operator keypair (64-byte private, 32-byte public).
      Give operator.pub to the worker as OPENSHIELD_DLP_INDEX_PUBKEY.

  build --type edm|record|idm --in <path> --key operator.key --out <file> [knobs]
      edm    : --in is a file, one sensitive value per line. [--target-fp 0.001]
      record : --in is a file, one record per line, cells --delim-separated. [--delim '\t'] [--threshold 2]
      idm    : --in is a directory, each file one sensitive document. [--fraction 0.3]
`)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outKey := fs.String("out-key", "", "path to write the raw Ed25519 private key (64 bytes)")
	outPub := fs.String("out-pub", "", "path to write the raw Ed25519 public key (32 bytes)")
	_ = fs.Parse(args)
	if *outKey == "" || *outPub == "" {
		fatal("keygen needs --out-key and --out-pub")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generating key: %v", err)
	}
	// 0600 for the private key — it signs the operator's trusted detection data.
	if err := os.WriteFile(*outKey, priv, 0o600); err != nil {
		fatal("writing private key: %v", err)
	}
	if err := os.WriteFile(*outPub, pub, 0o644); err != nil {
		fatal("writing public key: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote operator key %s and public key %s\n", *outKey, *outPub)
}

func build(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	typ := fs.String("type", "", "index type: edm | record | idm")
	in := fs.String("in", "", "input file (edm/record) or directory (idm)")
	keyPath := fs.String("key", "", "operator Ed25519 private key file (64 bytes)")
	out := fs.String("out", "", "output signed-index file")
	targetFP := fs.Float64("target-fp", 0.001, "edm: bloom-filter target false-positive rate")
	delim := fs.String("delim", "\t", "record: cell delimiter")
	threshold := fs.Int("threshold", 2, "record: distinct same-record cells required to match")
	fraction := fs.Float64("fraction", 0.3, "idm: fraction of a document's shingles required to match")
	_ = fs.Parse(args)

	if *typ == "" || *in == "" || *keyPath == "" || *out == "" {
		fatal("build needs --type, --in, --key, and --out")
	}
	priv := loadPrivKey(*keyPath)

	var kind string
	var indexBytes []byte
	switch *typ {
	case "edm":
		kind = classify.IndexKindEDM
		indexBytes = buildEDM(*in, *targetFP)
	case "record":
		kind = classify.IndexKindRecord
		indexBytes = buildRecord(*in, *delim, *threshold)
	case "idm":
		kind = classify.IndexKindIDM
		indexBytes = buildIDM(*in, *fraction)
	default:
		fatal("unknown --type %q (want edm|record|idm)", *typ)
	}

	signed, err := classify.SignIndex(kind, indexBytes, priv)
	if err != nil {
		fatal("signing index: %v", err)
	}
	if err := os.WriteFile(*out, signed, 0o644); err != nil {
		fatal("writing %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote signed %s index %s\n", kind, *out)
}

func buildEDM(path string, targetFP float64) []byte {
	values := readLines(path)
	if len(values) == 0 {
		fatal("edm: no values in %s", path)
	}
	idx := classify.NewEDMIndex(targetFP, len(values))
	for _, v := range values {
		idx.Add(v)
	}
	return idx.Marshal()
}

func buildRecord(path, delim string, threshold int) []byte {
	lines := readLines(path)
	if len(lines) == 0 {
		fatal("record: no records in %s", path)
	}
	records := make([][]string, 0, len(lines))
	for _, ln := range lines {
		records = append(records, strings.Split(ln, delim))
	}
	idx, skipped := classify.BuildRecordIndex(records, threshold)
	if idx.Size() == 0 {
		fatal("record: no records had enough distinctive cells (%d skipped) — nothing to index", skipped)
	}
	return idx.Marshal()
}

func buildIDM(dir string, fraction float64) []byte {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fatal("idm: reading directory %s: %v", dir, err)
	}
	var docs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			fatal("idm: reading %s: %v", e.Name(), err)
		}
		docs = append(docs, string(b))
	}
	if len(docs) == 0 {
		fatal("idm: no documents in %s", dir)
	}
	idx, skipped := classify.BuildDocumentIndex(docs, classify.DefaultShingleK, fraction)
	if idx.Size() == 0 {
		fatal("idm: no documents had enough shingles (%d skipped) — nothing to index", skipped)
	}
	return idx.Marshal()
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fatal("reading %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		fatal("reading %s: %v", path, err)
	}
	return out
}

func loadPrivKey(path string) ed25519.PrivateKey {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal("reading key %s: %v", path, err)
	}
	if len(b) != ed25519.PrivateKeySize {
		fatal("key %s is %d bytes, want %d (raw Ed25519 private key — see `keygen`)", path, len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "openshield-dlp-index: "+format+"\n", a...)
	os.Exit(1)
}
