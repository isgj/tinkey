package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestValidateInputOpts(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input.keyset")
	if err := os.WriteFile(in, []byte("keyset"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}
	missing := filepath.Join(dir, "missing.keyset")

	tests := []struct {
		name    string
		opts    cliOpts
		wantErr string
	}{
		{
			name:    "empty format matches nothing",
			opts:    cliOpts{},
			wantErr: "unsupported input format: ",
		},
		{
			name: "no flags with default format",
			opts: cliOpts{inFormat: "json"},
		},
		{
			name: "uppercase json format is accepted",
			opts: cliOpts{inFormat: "JSON"},
		},
		{
			name: "uppercase binary format is accepted",
			opts: cliOpts{inFormat: "Binary"},
		},
		{
			name:    "unsupported input format",
			opts:    cliOpts{inFormat: "PDF"},
			wantErr: "unsupported input format: pdf",
		},
		{
			name:    "missing input file",
			opts:    cliOpts{inFormat: "json", in: missing},
			wantErr: fmt.Sprintf("input file does not exist: %s", missing),
		},
		{
			name:    "input file is a directory",
			opts:    cliOpts{inFormat: "json", in: dir},
			wantErr: fmt.Sprintf("input file is a directory: %s", dir),
		},
		{name: "existing input file", opts: cliOpts{inFormat: "json", in: in}},
		{
			name:    "credential without master key",
			opts:    cliOpts{inFormat: "json", credential: in},
			wantErr: "credentials should be provided only if the master key is provided",
		},
		{name: "master key without credential", opts: cliOpts{inFormat: "json", masterKeyURI: "fake-kms://a"}},
		{
			name:    "missing credential file",
			opts:    cliOpts{inFormat: "json", masterKeyURI: "fake-kms://a", credential: missing},
			wantErr: fmt.Sprintf("credential file does not exist: %s", missing),
		},
		{
			name:    "credential file is a directory",
			opts:    cliOpts{inFormat: "json", masterKeyURI: "fake-kms://a", credential: dir},
			wantErr: fmt.Sprintf("credential file is a directory: %s", dir),
		},
		{name: "existing credential file", opts: cliOpts{inFormat: "json", masterKeyURI: "fake-kms://a", credential: in}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			wantErrEqual(t, tc.wantErr, validateInputOpts(&opts))
		})
	}
}

func TestValidateInputOptsNormalizesFormats(t *testing.T) {
	opts := cliOpts{inFormat: "JSON"}
	wantNoError(t, validateInputOpts(&opts))
	if opts.inFormat != "json" {
		t.Errorf("inFormat = %q, want normalized %q", opts.inFormat, "json")
	}
}

func TestValidateOutputOpts(t *testing.T) {
	dir := t.TempDir()
	existingOut := filepath.Join(dir, "existing.keyset")
	if err := os.WriteFile(existingOut, []byte("keyset"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}

	tests := []struct {
		name    string
		opts    cliOpts
		wantErr string
	}{
		{
			name:    "input validation runs before output validation",
			opts:    cliOpts{inFormat: "PDF", outFormat: "JSON"},
			wantErr: "unsupported input format: pdf",
		},
		{
			name:    "unsupported output format",
			opts:    cliOpts{inFormat: "json", outFormat: "PDF"},
			wantErr: "unsupported output format: pdf",
		},
		{
			name:    "output file already exists",
			opts:    cliOpts{inFormat: "json", outFormat: "json", out: existingOut},
			wantErr: fmt.Sprintf("output file already exists: %s", existingOut),
		},
		{
			name: "no output file means stdout",
			opts: cliOpts{inFormat: "json", outFormat: "json"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			wantErrEqual(t, tc.wantErr, validateOutputOpts(&opts))
		})
	}
}

func TestValidateOutputOptsNormalizesFormats(t *testing.T) {
	opts := cliOpts{inFormat: "json", outFormat: "BINARY"}
	wantNoError(t, validateOutputOpts(&opts))
	if opts.outFormat != "binary" {
		t.Errorf("outFormat = %q, want normalized %q", opts.outFormat, "binary")
	}
}

func TestValidateKeyIDOpts(t *testing.T) {
	tests := []struct {
		name    string
		opts    cliOpts
		wantErr string
	}{
		{
			name:    "key id is required",
			opts:    cliOpts{inFormat: "json", outFormat: "json"},
			wantErr: "flag key-id is required",
		},
		{
			name: "non-zero key id",
			opts: cliOpts{inFormat: "json", outFormat: "json", keyID: 1234},
		},
		{
			name:    "output validation still applies",
			opts:    cliOpts{inFormat: "json", outFormat: "PDF", keyID: 1234},
			wantErr: "unsupported output format: pdf",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			wantErrEqual(t, tc.wantErr, validateKeyIDOpts(&opts))
		})
	}
}

func TestValidateCreateKeysetOpts(t *testing.T) {
	tests := []struct {
		name    string
		opts    cliOpts
		wantErr string
	}{
		{
			name: "known template",
			opts: cliOpts{inFormat: "json", outFormat: "json", keyTemplate: "AES128_GCM"},
		},
		{
			name:    "unknown template",
			opts:    cliOpts{inFormat: "json", outFormat: "json", keyTemplate: "NO_SUCH_TEMPLATE"},
			wantErr: "unsupported key template: NO_SUCH_TEMPLATE",
		},
		{
			name:    "empty template",
			opts:    cliOpts{inFormat: "json", outFormat: "json", keyTemplate: ""},
			wantErr: "unsupported key template: ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			wantErrEqual(t, tc.wantErr, validateCreateKeysetOpts(&opts))
		})
	}
}

// TestValidateAddOptsRequiresKeyTemplate: add-key used to accept an empty
// --key-template and later panic on the nil template in addKey; validation
// must reject it up front.
func TestValidateAddOpts(t *testing.T) {
	tests := []struct {
		name    string
		opts    cliOpts
		wantErr string
	}{
		{
			name:    "empty key template is rejected",
			opts:    cliOpts{inFormat: "json", outFormat: "json", keyTemplate: ""},
			wantErr: "flag key-template is required",
		},
		{
			name:    "unknown key template",
			opts:    cliOpts{inFormat: "json", outFormat: "json", keyTemplate: "NO_SUCH_TEMPLATE"},
			wantErr: "unsupported key template: NO_SUCH_TEMPLATE",
		},
		{
			name: "known key template",
			opts: cliOpts{inFormat: "json", outFormat: "json", keyTemplate: "AES128_GCM"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			wantErrEqual(t, tc.wantErr, validateAddOpts(&opts))
		})
	}
}

// findFlag returns the flag with the given name, or fails the test.
func findFlag(t *testing.T, flags []cli.Flag, name string) cli.Flag {
	t.Helper()

	for _, f := range flags {
		if slices.Contains(f.Names(), name) {
			return f
		}
	}
	t.Fatalf("flag %q not found in %v", name, flags)
	return nil
}

func TestSharedFlagDefaults(t *testing.T) {
	tests := []struct {
		name      string
		flags     []cli.Flag
		wantFlag  string
		wantValue any
	}{
		{
			name:      "input in-format defaults to json",
			flags:     inputFlags(),
			wantFlag:  "in-format",
			wantValue: "json",
		},
		{
			name:      "output out-format defaults to json",
			flags:     outputFlags(),
			wantFlag:  "out-format",
			wantValue: "json",
		},
		{
			name:      "create-keyset key-template defaults to AES128_GCM",
			flags:     createFlags(),
			wantFlag:  "key-template",
			wantValue: "AES128_GCM",
		},
		{
			name:      "add-key key-template has no default",
			flags:     addKeyFlags(),
			wantFlag:  "key-template",
			wantValue: "",
		},
		{
			name:      "key-id has no default",
			flags:     keyIDFlags(),
			wantFlag:  "key-id",
			wantValue: uint(0),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := findFlag(t, tc.flags, tc.wantFlag)
			switch got := f.(type) {
			case *cli.StringFlag:
				if got.Value != tc.wantValue.(string) {
					t.Errorf("%s default = %q, want %q", tc.wantFlag, got.Value, tc.wantValue)
				}
			case *cli.UintFlag:
				if got.Value != tc.wantValue.(uint) {
					t.Errorf("%s default = %d, want %d", tc.wantFlag, got.Value, tc.wantValue)
				}
			}
		})
	}
}

// TestSharedFlagComposition checks that the flag builders compose the way the
// commands expect: each builder includes all flags of the smaller builder plus
// its own additions.
func TestSharedFlagComposition(t *testing.T) {
	tests := []struct {
		name        string
		flags       []cli.Flag
		wantFlags   []string
		wantMissing []string
	}{
		{
			name:        "input flags",
			flags:       inputFlags(),
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential"},
			wantMissing: []string{"out", "out-format", "key-id", "key-template"},
		},
		{
			name:        "output flags extend input flags",
			flags:       outputFlags(),
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential", "out", "out-format"},
			wantMissing: []string{"key-id", "key-template"},
		},
		{
			name:        "key-id flags extend output flags",
			flags:       keyIDFlags(),
			wantFlags:   []string{"out", "out-format", "key-id"},
			wantMissing: []string{"key-template"},
		},
		{
			name:        "create-keyset flags extend output flags",
			flags:       createFlags(),
			wantFlags:   []string{"out", "out-format", "key-template"},
			wantMissing: []string{"key-id"},
		},
		{
			name:        "add-key flags extend output flags",
			flags:       addKeyFlags(),
			wantFlags:   []string{"out", "out-format", "key-template"},
			wantMissing: []string{"key-id"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.wantFlags {
				findFlag(t, tc.flags, want)
			}
			for _, missing := range tc.wantMissing {
				for _, f := range tc.flags {
					if slices.Contains(f.Names(), missing) {
						t.Errorf("flags contain unexpected flag %q", missing)
						break
					}
				}
			}
		})
	}
}
