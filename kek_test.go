package main

import (
	"strings"
	"testing"
	// "github.com/tink-crypto/tink-go-awskms/v2/integration/awskms" // Not directly used for type assertion if Client is unexported
)

func TestGetKMSClient(t *testing.T) {
	tests := []struct {
		name           string
		uri            string
		credentialPath string
		expectErr      bool
		checkType      func(client interface{}) bool // Optional: more specific type check
	}{
		{
			name:           "AWS KMS URI without credentials",
			uri:            "aws-kms://arn:aws:kms:us-east-1:123456789012:key/mrk-12345678901234567890123456789012",
			credentialPath: "",
			expectErr:      false, // AWS SDK might not error here if it allows deferred credential loading
			checkType: func(client interface{}) bool {
				return client != nil // Basic check: client is not nil
			},
		},
		{
			name:           "AWS KMS URI with non-existent credentials file",
			uri:            "aws-kms://arn:aws:kms:us-east-1:123456789012:key/mrk-12345678901234567890123456789012",
			credentialPath: "testdata/non_existent_aws_credentials.json",
			expectErr:      true, // aws.NewClientWithOptions will err if file not found
			checkType:      nil,
		},
		{
			name:           "GCP KMS URI without credentials",
			uri:            "gcp-kms://projects/project/locations/loc/keyRings/kr/cryptoKeys/key",
			credentialPath: "",
			expectErr:      true, // Expect error if no default GCP credentials (ADC)
			checkType: func(client interface{}) bool {
				return client != nil // Basic check: client is not nil. Unreachable if expectErr is true.
			},
		},
		{
			name:           "Fake KMS URI",
			uri:            "fake-kms://some-fake-key",
			credentialPath: "",
			expectErr:      false, // Fake KMS should not error
			checkType: func(client interface{}) bool {
				return client != nil // Basic check: client is not nil
			},
		},
		{
			name:           "Unsupported URI",
			uri:            "unsupported-kms://some-key",
			credentialPath: "",
			expectErr:      true,
			checkType:      nil,
		},
		{
			name:           "Empty URI should error from getKMSClient",
			uri:            "", // If getKMSClient is called directly with empty URI
			credentialPath: "",
			expectErr:      true, // getKMSClient itself should reject an empty URI
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := getKMSClient(tt.uri, tt.credentialPath)

			if (err != nil) != tt.expectErr {
				t.Errorf("getKMSClient() error = %v, expectErr %v", err, tt.expectErr)
				// If error was expected and occurred, or not expected and didn't occur, continue
				if (err != nil) == tt.expectErr {
					return
				}
			}

			// If an error was expected and it occurred, the test for this case passes.
			if tt.expectErr && err != nil {
				// Optionally, check for specific error messages if robust
				// For "AWS KMS URI with non-existent credentials file":
				if tt.name == "AWS KMS URI with non-existent credentials file" {
					if !strings.Contains(err.Error(), "cannot open credential path") && !strings.Contains(err.Error(), "no such file or directory") {
						t.Errorf("Expected error related to credential file, got: %v", err)
					}
				}
				return
			}

			// If no error was expected, but one occurred.
			if !tt.expectErr && err != nil {
				t.Errorf("getKMSClient() unexpected error = %v", err)
				return
			}

			// If no error was expected and none occurred, check client and type.
			if !tt.expectErr && client == nil {
				t.Errorf("getKMSClient() expected a client but got nil")
				return
			}

			if tt.checkType != nil && !tt.expectErr {
				if !tt.checkType(client) {
					t.Errorf("getKMSClient() client type check failed for %T", client)
				}
			}
		})
	}
}
