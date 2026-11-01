package main

import (
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

func createKeysetCommand() *cli.Command {
	return &cli.Command{
		Name:   "create-keyset",
		Usage:  "Creates a new keyset.",
		Flags:  createFlags(),
		Action: commandAction(validateCreateKeysetOpts, createKeyset),
	}
}

func createPublicKeysetCommand() *cli.Command {
	return &cli.Command{
		Name:   "create-public-keyset",
		Usage:  "Creates a public keyset from a private keyset.",
		Flags:  outputFlags(),
		Action: commandAction(validateOutputOpts, createPublicKeyset),
	}
}

func createKeyset(opts *cliOpts) error {
	keyTemplate := supportedTemplates[opts.keyTemplate]
	kh, err := keyset.NewHandle(keyTemplate())
	if err != nil {
		return fmt.Errorf("failed to create keyset handle: %v", err)
	}

	masterAEAD, err := getKEK(opts.masterKeyURI, opts.credential)
	if err != nil {
		return fmt.Errorf("failed to get KEK: %v", err)
	}

	return writeKeyHandle(opts, kh, masterAEAD)
}

func createPublicKeyset(opts *cliOpts) error {
	masterAEAD, err := getKEK(opts.masterKeyURI, opts.credential)
	if err != nil {
		return fmt.Errorf("failed to get KEK: %v", err)
	}

	kh, err := readKeyHandle(opts, masterAEAD)
	if err != nil {
		return err
	}

	pkh, err := kh.Public()
	if err != nil {
		return fmt.Errorf("failed to get public key handle: %v", err)
	}

	return writeKeyHandle(opts, pkh, masterAEAD)
}
