package main

import (
	"bytes"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	"google.golang.org/protobuf/proto"
)

func TestAllSupportedTemplatesGenerateMeaningfulTemplates(t *testing.T) {
	for name, template := range supportedTemplates {
		t.Run(name, func(t *testing.T) {
			kt := template()
			if kt == nil {
				t.Fatal("template func returned nil")
			}
			if kt.GetTypeUrl() == "" {
				t.Error("template has an empty type URL")
			}
			// The format value is legitimately empty for templates without
			// tunable parameters, such as ED25519 or CHACHA20_POLY1305, so it
			// is not checked here.
			if kt.GetOutputPrefixType() == tink_go_proto.OutputPrefixType_UNKNOWN_PREFIX {
				t.Error("template has an unknown output prefix type")
			}
		})
	}
}

// TestRSATemplatesMatchTheirNames pins the mapping of the RSA_SSA_PKCS1
// template names. RSA_SSA_PKCS1_3072_SHA512_F4 used to be mapped to the
// 4096-bit template, so users asking for a 3072-bit key received a 4096-bit
// key instead.
func TestRSATemplatesMatchTheirNames(t *testing.T) {
	tests := []struct {
		name string
		want *tink_go_proto.KeyTemplate
	}{
		{name: "RSA_SSA_PKCS1_3072_SHA256_F4", want: signature.RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template()},
		{name: "RSA_SSA_PKCS1_4096_SHA512_F4", want: signature.RSA_SSA_PKCS1_4096_SHA512_F4_Key_Template()},
	}

	var gotNames []string
	for name := range supportedTemplates {
		if strings.HasPrefix(name, "RSA_SSA_PKCS1") {
			gotNames = append(gotNames, name)
		}
	}
	slices.Sort(gotNames)
	wantNames := []string{"RSA_SSA_PKCS1_3072_SHA256_F4", "RSA_SSA_PKCS1_4096_SHA512_F4"}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("RSA_SSA_PKCS1 template names = %v, want %v", gotNames, wantNames)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := supportedTemplates[tc.name](); !proto.Equal(got, tc.want) {
				t.Errorf("template = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestListKeyTemplatesOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := listKeyTemplates(&buf, &cliOpts{}); err != nil {
		t.Fatalf("listKeyTemplates() error: %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if want := "The following key template names are recognized:"; lines[0] != want {
		t.Errorf("header = %q, want %q", lines[0], want)
	}

	var gotNames []string
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("template line %q is not indented: %q", line, line)
			continue
		}
		gotNames = append(gotNames, strings.TrimPrefix(line, "  "))
	}

	wantNames := slices.Sorted(maps.Keys(supportedTemplates))
	if !slices.Equal(gotNames, wantNames) {
		t.Errorf("listed templates = %v, want %v", gotNames, wantNames)
	}
	if !slices.IsSorted(gotNames) {
		t.Errorf("listed templates are not sorted: %v", gotNames)
	}
}
