package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"slices"
	"testing"

	"github.com/urfave/cli/v3"
)

// TestSubcommandFlagWiring asserts that every subcommand declares the flags
// its validation and run code reads. A command whose constructor forgets to
// set Flags (as list-keyset once did) parses fine but fails at runtime with
// "flag provided but not defined", so this must be checked statically.
func TestSubcommandFlagWiring(t *testing.T) {
	tests := []struct {
		command     func() *cli.Command
		wantFlags   []string
		wantMissing []string
	}{
		{
			command:     addKeyCommand,
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential", "out", "out-format", "key-template"},
			wantMissing: []string{"key-id"},
		},
		{
			command:     createKeysetCommand,
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential", "out", "out-format", "key-template"},
			wantMissing: []string{"key-id"},
		},
		{
			command:     createPublicKeysetCommand,
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential", "out", "out-format"},
			wantMissing: []string{"key-id", "key-template"},
		},
		{
			command:     deleteKeyCommand,
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential", "out", "out-format", "key-id"},
			wantMissing: []string{"key-template"},
		},
		{
			command:     disableKeyCommand,
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential", "out", "out-format", "key-id"},
			wantMissing: []string{"key-template"},
		},
		{
			command:     enableKeyCommand,
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential", "out", "out-format", "key-id"},
			wantMissing: []string{"key-template"},
		},
		{
			command:     listKeysetCommand,
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential"},
			wantMissing: []string{"out", "out-format", "key-id", "key-template"},
		},
		{
			command:     promoteKeyCommand,
			wantFlags:   []string{"in", "in-format", "master-key-uri", "credential", "out", "out-format", "key-id"},
			wantMissing: []string{"key-template"},
		},
	}

	for _, tc := range tests {
		name := tc.command().Name
		t.Run(name, func(t *testing.T) {
			flags := tc.command().Flags
			if flags == nil {
				t.Fatal("command declares no Flags")
			}
			for _, want := range tc.wantFlags {
				found := false
				for _, f := range flags {
					if slices.Contains(f.Names(), want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("command %q lacks flag %q", name, want)
				}
			}
			for _, missing := range tc.wantMissing {
				for _, f := range flags {
					if slices.Contains(f.Names(), missing) {
						t.Errorf("command %q has unexpected flag %q", name, missing)
						break
					}
				}
			}
		})
	}
}

func TestRootCommandHelpListsAllSubcommands(t *testing.T) {
	root := newRootCommand()
	buf := new(bytes.Buffer)
	root.Writer = buf
	root.ErrWriter = buf

	if err := root.Run(context.Background(), []string{"tinkey", "--help"}); err != nil {
		t.Fatalf("Run(--help) error: %v", err)
	}

	for _, sub := range root.Commands {
		if sub.Hidden {
			// The library-injected "completion" command is hidden.
			continue
		}
		if !bytes.Contains(buf.Bytes(), []byte(sub.Name)) {
			t.Errorf("root help does not mention subcommand %q:\n%s", sub.Name, buf.String())
		}
	}
}

func TestRootCommandUnknownSubcommand(t *testing.T) {
	root := newRootCommand()
	root.Writer = io.Discard
	root.ErrWriter = io.Discard

	err := root.Run(context.Background(), []string{"tinkey", "nope"})
	wantErrEqual(t, "unknown command 'nope'", err)
}

func TestRootCommandWithoutSubcommand(t *testing.T) {
	root := newRootCommand()
	root.Writer = io.Discard
	root.ErrWriter = io.Discard

	err := root.Run(context.Background(), []string{"tinkey"})
	wantErrEqual(t, "expected a subcommand", err)
}

func TestRootCommandCompletionScript(t *testing.T) {
	// bash/zsh/fish scripts interpolate the app name; the pwsh script
	// derives it from its own filename at runtime.
	tests := []struct {
		shell      string
		embedsName bool
	}{
		{shell: "bash", embedsName: true},
		{shell: "zsh", embedsName: true},
		{shell: "fish", embedsName: true},
		{shell: "pwsh", embedsName: false},
	}

	for _, tc := range tests {
		t.Run(tc.shell, func(t *testing.T) {
			root := newRootCommand()
			buf := new(bytes.Buffer)
			root.Writer = buf
			root.ErrWriter = buf

			wantNoError(t, root.Run(context.Background(), []string{"tinkey", "completion", tc.shell}))

			if buf.Len() == 0 {
				t.Fatalf("%s completion script is empty", tc.shell)
			}
			if tc.embedsName && !bytes.Contains(buf.Bytes(), []byte("tinkey")) {
				t.Errorf("%s completion script does not mention the app name:\n%s", tc.shell, buf.String())
			}
		})
	}
	// Note: the hidden --generate-shell-completion flag cannot be asserted
	// in-process: for the root command DefaultCompleteWithFlags reads
	// os.Args rather than the argv passed to Run, so dynamic completion is
	// only meaningful in the real binary (covered by manual smoke tests).
}

// TestRootCommandListKeyTemplates dispatches through the full argv chain of
// the root command to verify the subcommand wiring end to end.
func TestRootCommandListKeyTemplates(t *testing.T) {
	root := newRootCommand()
	buf := new(bytes.Buffer)
	root.Writer = buf
	root.ErrWriter = buf

	wantNoError(t, root.Run(context.Background(), []string{"tinkey", "list-key-templates"}))

	out := buf.String()
	for name := range supportedTemplates {
		if !bytes.Contains(buf.Bytes(), []byte(name)) {
			t.Errorf("list-key-templates output lacks template %q:\n%s", name, out)
		}
	}
}

func TestAddKeyCommandRefusesMissingTemplate(t *testing.T) {
	cmd := addKeyCommand()
	cmd.Writer = io.Discard
	cmd.ErrWriter = io.Discard

	err := cmd.Run(context.Background(), []string{"add-key"})
	wantErrEqual(t, "flag key-template is required", err)
}

func TestSubcommandFlagParseError(t *testing.T) {
	cmd := addKeyCommand()
	cmd.Writer = io.Discard
	cmd.ErrWriter = io.Discard

	err := cmd.Run(context.Background(), []string{"add-key", "--nope"})
	wantErrContains(t, err, "not defined")
}

func TestCreateKeysetCommandRunCreatesKeyset(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "keyset.json")
	cmd := createKeysetCommand()
	cmd.Writer = io.Discard
	cmd.ErrWriter = io.Discard

	wantNoError(t, cmd.Run(context.Background(), []string{"create-keyset", "--out", out}))

	kh := readKeysetFile(t, out, "json", &plainText{})
	if kh.Len() != 1 {
		t.Fatalf("created keyset has %d keys, want 1", kh.Len())
	}
}
