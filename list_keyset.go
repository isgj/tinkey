package main

import (
	"fmt"
	"io"
)

func listKeyset(to io.Writer, opts *cliOpts) error {
	masterAEAD, err := getKEK(opts.masterKeyURI, opts.credential)
	if err != nil {
		return fmt.Errorf("failed to get KEK: %v", err)
	}

	kh, err := readKeyHandle(opts, masterAEAD)
	if err != nil {
		return err
	}

	fmt.Fprintf(to, "%12s %9s %9s\n", "Key ID", "Status", "Primary")
	for i := range kh.Len() {
		e, err := kh.Entry(i)
		if err != nil {
			return fmt.Errorf("error reading key: %v", err)
		}

		fmt.Fprintf(to, "%12d %9s %9t\n", e.KeyID(), e.KeyStatus(), e.IsPrimary())
	}

	return nil
}
