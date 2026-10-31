package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

// listHeader is the exact header line listKeyset must print for the
// "%12s %9s %9s" column layout of "Key ID", "Status" and "Primary".
const listHeader = "      Key ID    Status   Primary"

func TestListKeysetSingleKey(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			file := createKeysetFile(t, filepath.Join(dir, "keyset.json"), "AES128_GCM", variant)
			kh := readKeysetFile(t, file, "json", variant.masterAEAD)
			key := entries(t, kh)[0]

			var buf bytes.Buffer
			opts := &cliOpts{in: file, inFormat: "json", masterKeyURI: variant.masterKeyURI}
			wantNoError(t, listKeyset(&buf, opts))

			want := listHeader + "\n"
			want += fmt.Sprintf("%12d %9s %9t\n", key.KeyID(), key.KeyStatus(), key.IsPrimary())
			if buf.String() != want {
				t.Errorf("listKeyset() = %q, want %q", buf.String(), want)
			}
		})
	}
}

func TestListKeysetWithDisabledKey(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			_, secondary, baseID, secondaryID := createTwoKeyKeyset(t, dir, variant)

			disabled := filepath.Join(dir, "disabled.json")
			opts := &cliOpts{
				in:           secondary,
				inFormat:     "json",
				out:          disabled,
				outFormat:    "json",
				masterKeyURI: variant.masterKeyURI,
				keyID:        uint(secondaryID),
			}
			wantNoError(t, disableKey(opts))

			final := readKeysetFile(t, disabled, "json", variant.masterAEAD)
			khEntries := entries(t, final)
			if len(khEntries) != 2 {
				t.Fatalf("keyset has %d keys, want 2", len(khEntries))
			}
			if got := khEntries[0].KeyID(); got != baseID {
				t.Fatalf("first key ID = %d, want %d", got, baseID)
			}
			if got := khEntries[1].KeyID(); got != secondaryID {
				t.Fatalf("second key ID = %d, want %d", got, secondaryID)
			}

			want := listHeader + "\n"
			want += fmt.Sprintf("%12d %9s %9t\n", baseID, keyset.Enabled, true)
			want += fmt.Sprintf("%12d %9s %9t\n", secondaryID, keyset.Disabled, false)

			var buf bytes.Buffer
			opts = &cliOpts{in: disabled, inFormat: "json", masterKeyURI: variant.masterKeyURI}
			wantNoError(t, listKeyset(&buf, opts))
			if buf.String() != want {
				t.Errorf("listKeyset() = %q, want %q", buf.String(), want)
			}
		})
	}
}

func TestListKeysetErrors(t *testing.T) {
	dir := t.TempDir()

	junk := filepath.Join(dir, "junk.json")
	if err := os.WriteFile(junk, []byte("this is not a keyset"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}

	uri, _ := newFakeMasterKey(t)
	otherURI, _ := newFakeMasterKey(t)
	encrypted := filepath.Join(dir, "encrypted.json")
	encOpts := &cliOpts{out: encrypted, outFormat: "json", keyTemplate: "AES128_GCM", masterKeyURI: uri}
	wantNoError(t, createKeyset(encOpts))

	tests := []struct {
		name    string
		opts    *cliOpts
		wantErr string
	}{
		{
			name:    "missing input file",
			opts:    &cliOpts{in: filepath.Join(dir, "missing.keyset")},
			wantErr: "error opening input file: open",
		},
		{
			name:    "not a keyset in binary format",
			opts:    &cliOpts{in: junk},
			wantErr: "failed to read keyset",
		},
		{
			name:    "not a keyset in json format",
			opts:    &cliOpts{in: junk, inFormat: "json"},
			wantErr: "failed to read keyset",
		},
		{
			name:    "encrypted with another master key",
			opts:    &cliOpts{in: encrypted, inFormat: "json", masterKeyURI: otherURI},
			wantErr: "failed to read keyset",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			wantErrContains(t, listKeyset(&buf, tc.opts), tc.wantErr)
		})
	}
}
