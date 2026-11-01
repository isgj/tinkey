package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"
)

// commandAction builds a cli.ActionFunc that reads the shared flags into
// cliOpts, validates them and runs the command.
func commandAction(validate func(*cliOpts) error, run func(*cliOpts) error) cli.ActionFunc {
	return func(ctx context.Context, cmd *cli.Command) error {
		opts := newCliOpts(cmd)
		if err := validate(opts); err != nil {
			return err
		}
		return run(opts)
	}
}

func newRootCommand() *cli.Command {
	return &cli.Command{
		Name:  "tinkey",
		Usage: "Manage Tink keysets.",
		Description: "Tinkey is a tool to manage Tink keysets: creating, reading, updating and " +
			"listing them, optionally encrypted at rest with a KMS master key.",
		Commands: []*cli.Command{
			addKeyCommand(),
			createKeysetCommand(),
			createPublicKeysetCommand(),
			deleteKeyCommand(),
			disableKeyCommand(),
			enableKeyCommand(),
			listKeysetCommand(),
			listKeyTemplatesCommand(),
			promoteKeyCommand(),
		},
		// Generates the hidden "completion" subcommand and the dynamic
		// completion flag the sourced shell scripts rely on.
		EnableShellCompletion: true,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			// cli hands execution to this fallback when the first positional
			// argument does not match a subcommand, or when no arguments are
			// given at all.
			cli.HelpPrinter(cmd.Root().ErrWriter, cli.RootCommandHelpTemplate, cmd.Root())
			if cmd.Args().Present() {
				return fmt.Errorf("unknown command '%s'", cmd.Args().First())
			}
			return errors.New("expected a subcommand")
		},
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := newRootCommand()
	if err := root.Run(ctx, os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
