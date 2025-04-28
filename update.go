package main

import "github.com/tink-crypto/tink-go/v2/keyset"

func addKey(opts *cliOpts) error {
	return updateKeyset(opts, func(manager *keyset.Manager) error {
		keyTemplate := supportedTemplates[opts.keyTemplate]
		_, err := manager.Add(keyTemplate())
		return err
	})
}

func deleteKey(opts *cliOpts) error {
	return updateKeyset(opts, func(manager *keyset.Manager) error {
		return manager.Delete(uint32(opts.keyID))
	})
}

func disableKey(opts *cliOpts) error {
	return updateKeyset(opts, func(manager *keyset.Manager) error {
		return manager.Disable(uint32(opts.keyID))
	})
}

func enableKey(opts *cliOpts) error {
	return updateKeyset(opts, func(manager *keyset.Manager) error {
		return manager.Enable(uint32(opts.keyID))
	})
}

func promoteKey(opts *cliOpts) error {
	return updateKeyset(opts, func(manager *keyset.Manager) error {
		return manager.SetPrimary(uint32(opts.keyID))
	})
}
