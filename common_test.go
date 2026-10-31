package main

import (
	"os"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// keysetVariant parametrizes tests over the master key: cleartext keysets vs.
// keysets encrypted with a fake KMS master key.
type keysetVariant struct {
	name         string
	masterKeyURI string
	// masterAEAD mirrors what getKEK(masterKeyURI, "") returns and is used to
	// read and write files directly in tests.
	masterAEAD tink.AEAD
}

// newFakeMasterKey returns a fake-kms:// master key URI with a freshly
// generated master key, and a reference AEAD backed by the same key.
func newFakeMasterKey(t *testing.T) (string, tink.AEAD) {
	t.Helper()

	uri, err := fakekms.NewKeyURI()
	if err != nil {
		t.Fatalf("fakekms.NewKeyURI() error: %v", err)
	}
	aead, err := fakekms.NewAEAD(uri)
	if err != nil {
		t.Fatalf("fakekms.NewAEAD(%q) error: %v", uri, err)
	}
	return uri, aead
}

// masterKeyVariants covers both cleartext and fake-KMS-encrypted keysets.
func masterKeyVariants(t *testing.T) []keysetVariant {
	t.Helper()

	uri, aead := newFakeMasterKey(t)
	return []keysetVariant{
		{name: "cleartext", masterKeyURI: "", masterAEAD: &plainText{}},
		{name: "fake-kms", masterKeyURI: uri, masterAEAD: aead},
	}
}

// createKeysetFile creates a keyset file with the create-keyset command logic.
func createKeysetFile(t *testing.T, path, template string, variant keysetVariant) string {
	t.Helper()

	opts := &cliOpts{
		out:          path,
		outFormat:    "json",
		keyTemplate:  template,
		masterKeyURI: variant.masterKeyURI,
	}
	if err := createKeyset(opts); err != nil {
		t.Fatalf("createKeyset(out=%q, template=%q) error: %v", path, template, err)
	}
	return path
}

// readKeysetFile reads a keyset file with the same logic the CLI commands use.
func readKeysetFile(t *testing.T, path, inFormat string, masterAEAD tink.AEAD) *keyset.Handle {
	t.Helper()

	kh, err := readKeyHandle(&cliOpts{in: path, inFormat: inFormat}, masterAEAD)
	if err != nil {
		t.Fatalf("readKeyHandle(in=%q, format=%q) error: %v", path, inFormat, err)
	}
	return kh
}

// entries returns all entries of a keyset handle.
func entries(t *testing.T, kh *keyset.Handle) []*keyset.Entry {
	t.Helper()

	es := make([]*keyset.Entry, 0, kh.Len())
	for i := range kh.Len() {
		e, err := kh.Entry(i)
		if err != nil {
			t.Fatalf("kh.Entry(%d) error: %v", i, err)
		}
		es = append(es, e)
	}
	return es
}

// firstKeyID returns the ID of the first entry of a keyset handle.
func firstKeyID(t *testing.T, kh *keyset.Handle) uint32 {
	t.Helper()

	return entries(t, kh)[0].KeyID()
}

// entryByID returns the entry with the given key ID, or fails the test.
func entryByID(t *testing.T, kh *keyset.Handle, keyID uint32) *keyset.Entry {
	t.Helper()

	for _, e := range entries(t, kh) {
		if e.KeyID() == keyID {
			return e
		}
	}
	t.Fatalf("key ID %d not found in keyset", keyID)
	return nil
}

// otherKeyID returns the ID of the key that is not excludedID and fails the
// test if there is none.
func otherKeyID(t *testing.T, kh *keyset.Handle, excludedID uint32) uint32 {
	t.Helper()

	for _, e := range entries(t, kh) {
		if e.KeyID() != excludedID {
			return e.KeyID()
		}
	}
	t.Fatalf("keyset has no key other than ID %d", excludedID)
	return 0
}

// wantNoError fails the test if err is not nil.
func wantNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("error is not nil: %v", err)
	}
}

// wantErrEqual fails the test unless err is exactly wantErr ("" means nil).
func wantErrEqual(t *testing.T, wantErr string, err error) {
	t.Helper()

	switch {
	case wantErr == "" && err != nil:
		t.Fatalf("error is %q, want no error", err)
	case wantErr != "" && err == nil:
		t.Fatalf("error is nil, want %q", wantErr)
	case wantErr != "" && err != nil && err.Error() != wantErr:
		t.Fatalf("error is %q, want %q", err, wantErr)
	}
}

// wantErrContains fails the test unless err is non-nil and contains substr.
func wantErrContains(t *testing.T, err error, substr string) {
	t.Helper()

	if err == nil {
		t.Fatalf("error is nil, want error containing %q", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error is %q, want error containing %q", err, substr)
	}
}

// assertFileExists fails the test if path does not exist.
func assertFileExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file %q should exist, stat error: %v", path, err)
	}
}

// assertFileMissing fails the test if path exists.
func assertFileMissing(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err == nil {
		t.Fatalf("file %q should not exist", path)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %q error: %v", path, err)
	}
}
