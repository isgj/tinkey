package main

import (
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

func addKeyCommand() *cli.Command {
	return &cli.Command{
		Name:   "add-key",
		Usage:  "Generates and adds a new key to a keyset.",
		Flags:  addKeyFlags(),
		Action: commandAction(validateAddOpts, addKey),
	}
}

func addKey(opts *cliOpts) error {
	keyTemplate, ok := supportedTemplates[opts.keyTemplate]
	if !ok {
		return fmt.Errorf("unsupported key template: %s", opts.keyTemplate)
	}

	return updateKeyset(opts, func(manager *keyset.Manager) error {
		_, err := manager.Add(keyTemplate())
		return err
	})
}

func deleteKeyCommand() *cli.Command {
	return &cli.Command{
		Name:   "delete-key",
		Usage:  "Deletes a specified key in a keyset.",
		Flags:  keyIDFlags(),
		Action: commandAction(validateKeyIDOpts, deleteKey),
	}
}

func deleteKey(opts *cliOpts) error {
	return updateKeyset(opts, func(manager *keyset.Manager) error {
		return manager.Delete(uint32(opts.keyID))
	})
}

func disableKeyCommand() *cli.Command {
	return &cli.Command{
		Name:   "disable-key",
		Usage:  "Disables a specified key in a keyset.",
		Flags:  keyIDFlags(),
		Action: commandAction(validateKeyIDOpts, disableKey),
	}
}

func disableKey(opts *cliOpts) error {
	return updateKeyset(opts, func(manager *keyset.Manager) error {
		return manager.Disable(uint32(opts.keyID))
	})
}

func enableKeyCommand() *cli.Command {
	return &cli.Command{
		Name:   "enable-key",
		Usage:  "Enables a specified key in a keyset.",
		Flags:  keyIDFlags(),
		Action: commandAction(validateKeyIDOpts, enableKey),
	}
}

func enableKey(opts *cliOpts) error {
	return updateKeyset(opts, func(manager *keyset.Manager) error {
		return manager.Enable(uint32(opts.keyID))
	})
}

func promoteKeyCommand() *cli.Command {
	return &cli.Command{
		Name:   "promote-key",
		Usage:  "Promotes a specified key to primary.",
		Flags:  keyIDFlags(),
		Action: commandAction(validateKeyIDOpts, promoteKey),
	}
}

func promoteKey(opts *cliOpts) error {
	return updateKeyset(opts, func(manager *keyset.Manager) error {
		return manager.SetPrimary(uint32(opts.keyID))
	})
}
