package main

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

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
