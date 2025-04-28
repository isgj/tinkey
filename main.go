package main

import (
	"flag"
	"fmt"
	"os"
)

func printUsage() {
	const usage = `Usage: %s <command> [flags]

Available commands:
  add-key               Generates and adds a new key to a keyset.
  create-keyset         Creates a new keyset.
  create-public-keyset  Creates a public keyset from a private keyset.
  delete-key            Deletes a specified key in a keyset.
  disable-key           Disables a specified key in a keyset.
  enable-key            Enables a specified key in a keyset.
  list-keyset           Lists keys in a keyset.
  list-key-templates    Lists all supported key templates.
  promote-key           Promotes a specified key to primary.

Use '<command> --help' for more information on a specific command.
`
	fmt.Fprintf(os.Stderr, usage, os.Args[0])
}

type command struct {
	flags    func(cmd *flag.FlagSet, opts *cliOpts)
	validate func(opts *cliOpts) error
	run      func(opts *cliOpts) error
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	commands := map[string]command{
		"add-key":              {flags: registerAddOpts, validate: validateAddOpts, run: addKey},
		"create-keyset":        {flags: registerCreateKeysetOpts, validate: validateCreateKeysetOpts, run: createKeyset},
		"create-public-keyset": {flags: registerOutputOpts, validate: validateOutputOpts, run: createPublicKeyset},
		"delete-key":           {flags: registerKeyIDOpts, validate: validateKeyIDOpts, run: deleteKey},
		"disable-key":          {flags: registerKeyIDOpts, validate: validateKeyIDOpts, run: disableKey},
		"enable-key":           {flags: registerKeyIDOpts, validate: validateKeyIDOpts, run: enableKey},
		"list-keyset":          {flags: registerInputOpts, validate: validateInputOpts, run: listKeyset},
		"list-key-templates": {
			flags:    func(*flag.FlagSet, *cliOpts) {},
			validate: func(*cliOpts) error { return nil },
			run:      listKeyTemplates,
		},
		"promote-key": {flags: registerKeyIDOpts, validate: validateKeyIDOpts, run: promoteKey},
	}

	command, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: Unknown command '%s'\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	// --- Parse Flags ---
	opts := cliOpts{}

	cmd := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	command.flags(cmd, &opts)

	err := cmd.Parse(os.Args[2:])
	if err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if err := command.validate(&opts); err != nil {
		fmt.Printf("%v\n", err)
		cmd.Usage()
		os.Exit(1)
	}

	// --- Run Command ---
	if err := command.run(&opts); err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}
