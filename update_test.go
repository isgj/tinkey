package main

import (
	"path/filepath"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

// createTwoKeyKeyset creates a one-key keyset and adds a secondary key to a
// second file. It returns the file paths and both generated key IDs.
func createTwoKeyKeyset(t *testing.T, dir string, variant keysetVariant) (base, secondary string, baseID, secondaryID uint32) {
	t.Helper()

	base = filepath.Join(dir, "base.json")
	createKeysetFile(t, base, "AES128_GCM", variant)
	baseID = firstKeyID(t, readKeysetFile(t, base, "json", variant.masterAEAD))

	secondary = filepath.Join(dir, "two-keys.json")
	opts := &cliOpts{
		in:           base,
		inFormat:     "json",
		out:          secondary,
		outFormat:    "json",
		keyTemplate:  "AES256_GCM",
		masterKeyURI: variant.masterKeyURI,
	}
	if err := addKey(opts); err != nil {
		t.Fatalf("addKey() error: %v", err)
	}

	kh := readKeysetFile(t, secondary, "json", variant.masterAEAD)
	if kh.Len() != 2 {
		t.Fatalf("keyset has %d keys, want 2", kh.Len())
	}
	secondaryID = otherKeyID(t, kh, baseID)
	return base, secondary, baseID, secondaryID
}

func TestAddKeyAddsSecondaryKey(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			base, updated, baseID, secondaryID := createTwoKeyKeyset(t, dir, variant)

			// The input file must not be modified; updates go to the output
			// file only.
			if count := readKeysetFile(t, base, "json", variant.masterAEAD).Len(); count != 1 {
				t.Errorf("input keyset has %d keys, want 1", count)
			}

			kh := readKeysetFile(t, updated, "json", variant.masterAEAD)
			if kh.Len() != 2 {
				t.Fatalf("updated keyset has %d keys, want 2", kh.Len())
			}

			secondary := entryByID(t, kh, secondaryID)
			if secondary.KeyStatus() != keyset.Enabled {
				t.Errorf("added key status = %v, want Enabled", secondary.KeyStatus())
			}
			if secondary.IsPrimary() {
				t.Error("added key is primary, want it to stay secondary")
			}

			if primary := entryByID(t, kh, baseID); !primary.IsPrimary() {
				t.Error("original key lost its primary status after add-key")
			}
		})
	}
}

func TestAddKeyConvertsOutputFormat(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			base := createKeysetFile(t, filepath.Join(dir, "base.json"), "AES128_GCM", variant)

			out := filepath.Join(dir, "out.bin")
			opts := &cliOpts{
				in:           base,
				inFormat:     "json",
				out:          out,
				outFormat:    "binary",
				keyTemplate:  "AES256_GCM",
				masterKeyURI: variant.masterKeyURI,
			}
			if err := addKey(opts); err != nil {
				t.Fatalf("addKey() error: %v", err)
			}

			if kh := readKeysetFile(t, out, "binary", variant.masterAEAD); kh.Len() != 2 {
				t.Fatalf("updated keyset has %d keys, want 2", kh.Len())
			}
		})
	}
}

// TestAddKeyWithEmptyTemplateCannotPanic is a regression test: add-key used to
// dereference the nil key template when --key-template was omitted, causing a
// nil pointer panic in addKey. It must return an error instead and leave the
// output file untouched.
func TestAddKeyWithEmptyTemplateCannotPanic(t *testing.T) {
	dir := t.TempDir()
	base := createKeysetFile(t, filepath.Join(dir, "base.json"), "AES128_GCM",
		keysetVariant{name: "cleartext", masterKeyURI: "", masterAEAD: &plainText{}})

	out := filepath.Join(dir, "out.json")
	err := addKey(&cliOpts{in: base, inFormat: "json", out: out, outFormat: "json"})
	wantErrEqual(t, "unsupported key template: ", err)
	assertFileMissing(t, out)
}

func TestAddKeyRefusesMissingInputFile(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "missing.keyset")
	out := filepath.Join(dir, "out.json")
	err := addKey(&cliOpts{
		in:          missing,
		inFormat:    "json",
		out:         out,
		outFormat:   "json",
		keyTemplate: "AES128_GCM",
	})
	wantErrContains(t, err, "error opening input file: open")
	assertFileMissing(t, out)
}

func TestDeleteKeyRemovesSecondaryKey(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			_, secondary, baseID, secondaryID := createTwoKeyKeyset(t, dir, variant)

			out := filepath.Join(dir, "deleted.json")
			opts := &cliOpts{
				in:           secondary,
				inFormat:     "json",
				out:          out,
				outFormat:    "json",
				masterKeyURI: variant.masterKeyURI,
				keyID:        uint(secondaryID),
			}
			if err := deleteKey(opts); err != nil {
				t.Fatalf("deleteKey() error: %v", err)
			}

			kh := readKeysetFile(t, out, "json", variant.masterAEAD)
			if kh.Len() != 1 {
				t.Fatalf("updated keyset has %d keys, want 1", kh.Len())
			}
			key := entries(t, kh)[0]
			if key.KeyID() != baseID {
				t.Errorf("remaining key ID = %d, want %d", key.KeyID(), baseID)
			}
			if !key.IsPrimary() {
				t.Error("remaining key lost its primary status")
			}
		})
	}
}

func TestDeleteKeyRefusesPrimary(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			_, secondary, baseID, _ := createTwoKeyKeyset(t, dir, variant)

			out := filepath.Join(dir, "deleted.json")
			opts := &cliOpts{
				in:           secondary,
				inFormat:     "json",
				out:          out,
				outFormat:    "json",
				masterKeyURI: variant.masterKeyURI,
				keyID:        uint(baseID),
			}
			err := deleteKey(opts)
			wantErrContains(t, err, "failed to update keyset")
			wantErrContains(t, err, "cannot delete the primary key")
			assertFileMissing(t, out)
		})
	}
}

func TestDeleteKeyRefusesUnknownKeyID(t *testing.T) {
	dir := t.TempDir()
	_, secondary, _, _ := createTwoKeyKeyset(t, dir,
		keysetVariant{name: "cleartext", masterKeyURI: "", masterAEAD: &plainText{}})

	out := filepath.Join(dir, "deleted.json")
	opts := &cliOpts{
		in:        secondary,
		inFormat:  "json",
		out:       out,
		outFormat: "json",
		keyID:     uint(0x12345678),
	}
	err := deleteKey(opts)
	wantErrContains(t, err, "failed to update keyset")
	wantErrContains(t, err, "not found")
	assertFileMissing(t, out)
}

func TestDisableKeyMarksSecondaryDisabled(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			_, secondary, baseID, secondaryID := createTwoKeyKeyset(t, dir, variant)

			out := filepath.Join(dir, "disabled.json")
			opts := &cliOpts{
				in:           secondary,
				inFormat:     "json",
				out:          out,
				outFormat:    "json",
				masterKeyURI: variant.masterKeyURI,
				keyID:        uint(secondaryID),
			}
			if err := disableKey(opts); err != nil {
				t.Fatalf("disableKey() error: %v", err)
			}

			kh := readKeysetFile(t, out, "json", variant.masterAEAD)
			if e := entryByID(t, kh, secondaryID); e.KeyStatus() != keyset.Disabled {
				t.Errorf("secondary key status = %v, want Disabled", e.KeyStatus())
			}
			if e := entryByID(t, kh, baseID); e.KeyStatus() != keyset.Enabled || !e.IsPrimary() {
				t.Errorf("primary key status = %v (primary=%t), want Enabled (primary=true)",
					e.KeyStatus(), e.IsPrimary())
			}
		})
	}
}

func TestDisableKeyRefusesPrimary(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			_, secondary, baseID, _ := createTwoKeyKeyset(t, dir, variant)

			out := filepath.Join(dir, "disabled.json")
			opts := &cliOpts{
				in:           secondary,
				inFormat:     "json",
				out:          out,
				outFormat:    "json",
				masterKeyURI: variant.masterKeyURI,
				keyID:        uint(baseID),
			}
			err := disableKey(opts)
			wantErrContains(t, err, "failed to update keyset")
			wantErrContains(t, err, "cannot disable the primary key")
			assertFileMissing(t, out)
		})
	}
}

func TestEnableKeyReEnablesDisabledKey(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			_, secondary, baseID, secondaryID := createTwoKeyKeyset(t, dir, variant)

			disabled := filepath.Join(dir, "disabled.json")
			disableOpts := &cliOpts{
				in:           secondary,
				inFormat:     "json",
				out:          disabled,
				outFormat:    "json",
				masterKeyURI: variant.masterKeyURI,
				keyID:        uint(secondaryID),
			}
			wantNoError(t, disableKey(disableOpts))

			out := filepath.Join(dir, "enabled.json")
			enableOpts := &cliOpts{
				in:           disabled,
				inFormat:     "json",
				out:          out,
				outFormat:    "json",
				masterKeyURI: variant.masterKeyURI,
				keyID:        uint(secondaryID),
			}
			if err := enableKey(enableOpts); err != nil {
				t.Fatalf("enableKey() error: %v", err)
			}

			kh := readKeysetFile(t, out, "json", variant.masterAEAD)
			if e := entryByID(t, kh, secondaryID); e.KeyStatus() != keyset.Enabled {
				t.Errorf("re-enabled key status = %v, want Enabled", e.KeyStatus())
			}
			if e := entryByID(t, kh, baseID); !e.IsPrimary() {
				t.Error("primary key changed after enable-key")
			}
		})
	}
}

func TestPromoteKeyPromotesSecondaryKey(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			_, secondary, baseID, secondaryID := createTwoKeyKeyset(t, dir, variant)

			out := filepath.Join(dir, "promoted.json")
			opts := &cliOpts{
				in:           secondary,
				inFormat:     "json",
				out:          out,
				outFormat:    "json",
				masterKeyURI: variant.masterKeyURI,
				keyID:        uint(secondaryID),
			}
			if err := promoteKey(opts); err != nil {
				t.Fatalf("promoteKey() error: %v", err)
			}

			kh := readKeysetFile(t, out, "json", variant.masterAEAD)
			if e := entryByID(t, kh, secondaryID); !e.IsPrimary() {
				t.Error("promoted key did not become primary")
			}
			if e := entryByID(t, kh, baseID); e.IsPrimary() {
				t.Error("original key is still primary after promote-key")
			}
			for _, e := range entries(t, kh) {
				if e.KeyStatus() != keyset.Enabled {
					t.Errorf("key %d status = %v, want Enabled", e.KeyID(), e.KeyStatus())
				}
			}
		})
	}
}

func TestPromoteKeyRefusesDisabledKey(t *testing.T) {
	dir := t.TempDir()
	_, secondary, _, secondaryID := createTwoKeyKeyset(t, dir,
		keysetVariant{name: "cleartext", masterKeyURI: "", masterAEAD: &plainText{}})

	disabled := filepath.Join(dir, "disabled.json")
	disableOpts := &cliOpts{
		in:        secondary,
		inFormat:  "json",
		out:       disabled,
		outFormat: "json",
		keyID:     uint(secondaryID),
	}
	wantNoError(t, disableKey(disableOpts))

	out := filepath.Join(dir, "promoted.json")
	promoteOpts := &cliOpts{
		in:        disabled,
		inFormat:  "json",
		out:       out,
		outFormat: "json",
		keyID:     uint(secondaryID),
	}
	err := promoteKey(promoteOpts)
	wantErrContains(t, err, "failed to update keyset")
	wantErrContains(t, err, "cannot set key as primary")
	assertFileMissing(t, out)
}
