package main

import (
	"context"
	"fmt"
	"io"

	"github.com/urfave/cli/v3"
)

func listKeysetCommand() *cli.Command {
	return &cli.Command{
		Name:  "list-keyset",
		Usage: "Lists keys in a keyset.",
		Flags: inputFlags(),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			opts := newCliOpts(cmd)
			if err := validateInputOpts(opts); err != nil {
				return err
			}
			return listKeyset(cmd.Root().Writer, opts)
		},
	}
}

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
