package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

func TestCreateKeyset(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		for _, outFormat := range []string{"json", "binary"} {
			t.Run(variant.name+"-"+outFormat, func(t *testing.T) {
				dir := t.TempDir()
				file := filepath.Join(dir, "keyset."+outFormat)
				opts := &cliOpts{
					out:          file,
					outFormat:    outFormat,
					keyTemplate:  "AES128_GCM",
					masterKeyURI: variant.masterKeyURI,
				}
				wantNoError(t, createKeyset(opts))

				kh := readKeysetFile(t, file, outFormat, variant.masterAEAD)
				if kh.Len() != 1 {
					t.Fatalf("keyset has %d keys, want 1", kh.Len())
				}
				key := entries(t, kh)[0]
				if key.KeyStatus() != keyset.Enabled {
					t.Errorf("key status = %v, want Enabled", key.KeyStatus())
				}
				if !key.IsPrimary() {
					t.Error("key is not primary")
				}
			})
		}
	}
}

func TestCreateKeysetEncryptedJSONContainsNoPlaintextKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	uri, ref := newFakeMasterKey(t)
	variant := keysetVariant{name: "fake-kms", masterKeyURI: uri, masterAEAD: ref}

	file := createKeysetFile(t, filepath.Join(dir, "keyset.json"), "AES128_GCM", variant)

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("os.ReadFile() error: %v", err)
	}

	// The JSON must wrap an encrypted keyset container and must not carry any
	// plaintext key data fields.
	if !strings.Contains(string(data), "encryptedKeyset") && !strings.Contains(string(data), "encrypted_keyset") {
		t.Errorf("encrypted keyset JSON has no encryptedKeyset field:\n%s", data)
	}
	if strings.Contains(string(data), "keyData") || strings.Contains(string(data), "key_data") {
		t.Errorf("encrypted keyset JSON contains plaintext key data:\n%s", data)
	}
}

func TestCreateKeysetRefusesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "keyset.json")
	opts := &cliOpts{out: file, outFormat: "json", keyTemplate: "AES128_GCM"}
	wantNoError(t, createKeyset(opts))

	wantErrContains(t, createKeyset(opts), "error opening output file")
}

func TestCreateKeysetUnsupportedMasterKeyURI(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "keyset.json")
	opts := &cliOpts{
		out:          file,
		outFormat:    "json",
		keyTemplate:  "AES128_GCM",
		masterKeyURI: "unsupported-kms://key",
	}
	wantErrContains(t, createKeyset(opts), "failed to get KEK")
	assertFileMissing(t, file)
}

func TestCreatePublicKeysetFromAsymmetricKeyset(t *testing.T) {
	for _, variant := range masterKeyVariants(t) {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			base := createKeysetFile(t, filepath.Join(dir, "private.json"), "ECDSA_P256", variant)

			pub := filepath.Join(dir, "public.json")
			opts := &cliOpts{
				in:           base,
				inFormat:     "json",
				out:          pub,
				outFormat:    "json",
				masterKeyURI: variant.masterKeyURI,
			}
			wantNoError(t, createPublicKeyset(opts))
			assertFileExists(t, pub)

			kh := readKeysetFile(t, pub, "json", variant.masterAEAD)
			if kh.Len() != 1 {
				t.Fatalf("public keyset has %d keys, want 1", kh.Len())
			}
		})
	}
}

func TestCreatePublicKeysetRefusesSymmetricKeyset(t *testing.T) {
	dir := t.TempDir()
	base := createKeysetFile(t, filepath.Join(dir, "symmetric.json"), "AES128_GCM",
		keysetVariant{name: "cleartext", masterKeyURI: "", masterAEAD: &plainText{}})

	pub := filepath.Join(dir, "public.json")
	opts := &cliOpts{in: base, inFormat: "json", out: pub, outFormat: "json"}
	wantErrContains(t, createPublicKeyset(opts), "failed to get public key handle")
	assertFileMissing(t, pub)
}
