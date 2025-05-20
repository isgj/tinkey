package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tink-crypto/tink-go-awskms/v2/integration/awskms" // AWS KMS
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms" // GCP KMS
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/api/option" // For GCP KMS options
)

func getKEK(masterKeyURI, credentialPath string) (tink.AEAD, error) {
	if masterKeyURI == "" {
		return &plainText{}, nil
	}

	kmsClient, err := getKMSClient(masterKeyURI, credentialPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS client for %s: %v", masterKeyURI, err)
	}
	masterAEAD, err := kmsClient.GetAEAD(masterKeyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD from KMS for %s: %v", masterKeyURI, err)
	}
	return masterAEAD, nil
}

// getKMSClient initializes and returns a KMS client based on the URI.
func getKMSClient(uri, credPath string) (registry.KMSClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch {
	case strings.HasPrefix(uri, "gcp-kms://"):
		opts := []option.ClientOption{} // GCP options from google.golang.org/api/option
		if credPath != "" {
			opts = append(opts, option.WithCredentialsFile(credPath))
		}
		return gcpkms.NewClientWithOptions(ctx, uri, opts...)
	case strings.HasPrefix(uri, "fake-kms://"): // not documented on purpose
		return fakekms.NewClient(uri)
	case strings.HasPrefix(uri, "aws-kms://"):
		awsOpts := []awskms.ClientOption{} // AWS options from the awskms package
		if credPath != "" {
			awsOpts = append(awsOpts, awskms.WithCredentialPath(credPath))
		}
		return awskms.NewClientWithOptions(uri, awsOpts...)
		// Add logic for other KMS providers (AWS, etc.)
	}

	return nil, fmt.Errorf("unsupported KMS provider for URI: %s", uri)
}

type plainText struct{}

func (p *plainText) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return plaintext, nil
}

func (p *plainText) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if ciphertext == nil {
		return nil, fmt.Errorf("ciphertext is nil")
	}
	return ciphertext, nil
}
