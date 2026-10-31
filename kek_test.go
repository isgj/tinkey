package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlainTextPassthroughAEAD(t *testing.T) {
	aead := &plainText{}

	ct, err := aead.Encrypt([]byte("plaintext"), []byte("ad"))
	wantNoError(t, err)
	if !bytes.Equal(ct, []byte("plaintext")) {
		t.Errorf("Encrypt() = %q, want it passed through unchanged", ct)
	}

	got, err := aead.Decrypt(ct, []byte("ad"))
	wantNoError(t, err)
	if !bytes.Equal(got, []byte("plaintext")) {
		t.Errorf("Decrypt() = %q, want it passed through unchanged", got)
	}

	if _, err := aead.Decrypt(nil, nil); err == nil || !strings.Contains(err.Error(), "ciphertext is nil") {
		t.Errorf("Decrypt(nil) = %v, want an error about nil ciphertext", err)
	}
}

func TestGetKEKWithoutMasterKeyURIReturnsPlainTextAEAD(t *testing.T) {
	aead, err := getKEK("", "")
	wantNoError(t, err)
	if _, ok := aead.(*plainText); !ok {
		t.Errorf("getKEK() = %T, want *plainText", aead)
	}
}

func TestGetKEKUnsupportedMasterKeyURI(t *testing.T) {
	_, err := getKEK("unsupported-kms://key", "")
	wantErrContains(t, err, "failed to get KMS client for unsupported-kms://key")
	wantErrContains(t, err, "unsupported KMS provider for URI: unsupported-kms://key")
}

func TestGetKMSClientFakeKMS(t *testing.T) {
	uri, ref := newFakeMasterKey(t)
	otherURI, _ := newFakeMasterKey(t)

	client, err := getKMSClient(uri, "")
	wantNoError(t, err)

	aead, err := client.GetAEAD(uri)
	wantNoError(t, err)

	ct, err := aead.Encrypt([]byte("plaintext"), []byte("ad"))
	wantNoError(t, err)

	// The reference AEAD is an independent instance for the same URI, so it
	// must decrypt what the client AEAD encrypted: master keys live in the
	// URI, not in the client instance.
	got, err := ref.Decrypt(ct, []byte("ad"))
	wantNoError(t, err)
	if !bytes.Equal(got, []byte("plaintext")) {
		t.Errorf("ref.Decrypt() = %q, want \"plaintext\"", got)
	}

	// A URI other than the client's prefix is rejected.
	if _, err := client.GetAEAD(otherURI); err == nil || !strings.Contains(err.Error(), "keyURI must start with prefix") {
		t.Errorf("client.GetAEAD(otherURI) = %v, want an error about the URI prefix", err)
	}
}

func TestGetKEKFakeKMSIsStableAcrossInstantiations(t *testing.T) {
	uri, ref := newFakeMasterKey(t)

	first, err := getKEK(uri, "")
	wantNoError(t, err)
	second, err := getKEK(uri, "")
	wantNoError(t, err)

	ct, err := first.Encrypt([]byte("plaintext"), []byte("ad"))
	wantNoError(t, err)

	got, err := second.Decrypt(ct, []byte("ad"))
	wantNoError(t, err)
	if !bytes.Equal(got, []byte("plaintext")) {
		t.Errorf("second.Decrypt() = %q, want \"plaintext\"", got)
	}

	got, err = ref.Decrypt(ct, []byte("ad"))
	wantNoError(t, err)
	if !bytes.Equal(got, []byte("plaintext")) {
		t.Errorf("ref.Decrypt() = %q, want \"plaintext\"", got)
	}
}
