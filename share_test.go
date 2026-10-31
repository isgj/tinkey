package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

func TestWriteAndReadKeyHandleRoundTrip(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		for _, outFormat := range []string{"json", "binary"} {
			t.Run(variant.name+"-"+outFormat, func(t *testing.T) {
				dir := t.TempDir()
				out := filepath.Join(dir, "keyset."+outFormat)

				source, err := keyset.NewHandle(supportedTemplates["AES128_GCM"]())
				if err != nil {
					t.Fatalf("keyset.NewHandle() error: %v", err)
				}

				writeOpts := &cliOpts{out: out, outFormat: outFormat}
				if err := writeKeyHandle(writeOpts, source, variant.masterAEAD); err != nil {
					t.Fatalf("writeKeyHandle() error: %v", err)
				}

				back := readKeysetFile(t, out, outFormat, variant.masterAEAD)
				if back.Len() != source.Len() {
					t.Fatalf("round-trip keyset has %d keys, want %d", back.Len(), source.Len())
				}
				got, want := firstKeyID(t, back), firstKeyID(t, source)
				if got != want {
					t.Errorf("round-trip key ID = %d, want %d", got, want)
				}
			})
		}
	}
}

func TestWriteKeyHandleRefusesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "keyset.json")

	source, err := keyset.NewHandle(supportedTemplates["AES128_GCM"]())
	if err != nil {
		t.Fatalf("keyset.NewHandle() error: %v", err)
	}
	opts := &cliOpts{out: out, outFormat: "json"}

	wantNoError(t, writeKeyHandle(opts, source, &plainText{}))
	wantErrContains(t, writeKeyHandle(opts, source, &plainText{}), "error opening output file")
}

func TestStandardStreamFallbacks(t *testing.T) {
	w, closer, err := getOutputFile(&cliOpts{})
	wantNoError(t, err)
	closer()
	if w != os.Stdout {
		t.Errorf("getOutputFile() writer = %v, want os.Stdout", w)
	}

	r, closer, err := getInputFile(&cliOpts{})
	wantNoError(t, err)
	closer()
	if r != os.Stdin {
		t.Errorf("getInputFile() reader = %v, want os.Stdin", r)
	}
}

func TestReadKeyHandleRejectsFormatMismatch(t *testing.T) {
	dir := t.TempDir()
	jsonFile := filepath.Join(dir, "keyset.json")
	binaryFile := filepath.Join(dir, "keyset.bin")

	source, err := keyset.NewHandle(supportedTemplates["AES128_GCM"]())
	if err != nil {
		t.Fatalf("keyset.NewHandle() error: %v", err)
	}
	masterAEAD := &plainText{}

	if err := writeKeyHandle(&cliOpts{out: jsonFile, outFormat: "json"}, source, masterAEAD); err != nil {
		t.Fatalf("writeKeyHandle() error: %v", err)
	}
	if err := writeKeyHandle(&cliOpts{out: binaryFile, outFormat: "binary"}, source, masterAEAD); err != nil {
		t.Fatalf("writeKeyHandle() error: %v", err)
	}

	// JSON data parsed as binary.
	if _, err := readKeyHandle(&cliOpts{in: jsonFile, inFormat: "binary"}, masterAEAD); err == nil {
		t.Error("reading JSON data as binary succeeded, want an error")
	} else if !strings.Contains(err.Error(), "failed to read keyset") {
		t.Errorf("reading JSON data as binary = %q, want error containing %q", err, "failed to read keyset")
	}

	// Binary data parsed as JSON.
	if _, err := readKeyHandle(&cliOpts{in: binaryFile, inFormat: "json"}, masterAEAD); err == nil {
		t.Error("reading binary data as JSON succeeded, want an error")
	} else if !strings.Contains(err.Error(), "failed to read keyset") {
		t.Errorf("reading binary data as JSON = %q, want error containing %q", err, "failed to read keyset")
	}
}

func TestReadKeyHandleRefusesWrongMasterKey(t *testing.T) {
	dir := t.TempDir()

	uri, _ := newFakeMasterKey(t)
	_, ref := newFakeMasterKey(t)

	file := filepath.Join(dir, "keyset.json")
	opts := &cliOpts{out: file, outFormat: "json", keyTemplate: "AES128_GCM", masterKeyURI: uri}
	wantNoError(t, createKeyset(opts))

	_, err := readKeyHandle(&cliOpts{in: file, inFormat: "json"}, ref)
	wantErrContains(t, err, "failed to read keyset")
}

func TestReadKeyHandleRefusesMissingInputFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.keyset")

	_, err := readKeyHandle(&cliOpts{in: missing, inFormat: "json"}, &plainText{})
	wantErrContains(t, err, "error opening input file: open")
}

// TestUpdateKeysetRefusesInputFromAnotherMasterKey verifies that updateKeyset
// reads and writes with one and the same master key: an input keyset
// encrypted under a different master key must fail and leave no output.
func TestUpdateKeysetRefusesInputFromAnotherMasterKey(t *testing.T) {
	dir := t.TempDir()
	uri1, _ := newFakeMasterKey(t)
	uri2, _ := newFakeMasterKey(t)

	base := createKeysetFile(t, filepath.Join(dir, "base.json"), "AES128_GCM",
		keysetVariant{name: "fake-kms-1", masterKeyURI: uri1, masterAEAD: nil})

	out := filepath.Join(dir, "updated.json")
	err := addKey(&cliOpts{
		in:           base,
		inFormat:     "json",
		out:          out,
		outFormat:    "json",
		keyTemplate:  "AES256_GCM",
		masterKeyURI: uri2,
	})
	wantErrContains(t, err, "failed to read keyset")
	assertFileMissing(t, out)
}
