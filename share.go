package main

import (
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// Flags shared by the keyset-manipulating subcommands.

func inputFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "in",
			Usage: "The input filename, must exist, to read the keyset from or standard input if not specified",
		},
		&cli.StringFlag{
			Name:  "in-format",
			Usage: "The input format: json or binary (case-insensitive).",
			Value: "json",
		},
		&cli.StringFlag{
			Name: "master-key-uri",
			Usage: "The keyset might be encrypted with a master key in Google Cloud KMS or AWS KMS. " +
				"This option specifies the URI of the master key. " +
				"If missing, read or write cleartext keysets. " +
				"Google Cloud KMS keys have this format: " +
				"gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*. " +
				"AWS KMS keys have this format: " +
				"aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>.",
		},
		&cli.StringFlag{
			Name: "credential",
			Usage: "If --master-key-uri is specified, this option specifies the credentials file path. " +
				"Must exist if specified. If missing, use default credentials. " +
				"Google Cloud credentials are service account JSON files. " +
				"AWS credentials are properties files with the AWS access key ID is expected " +
				"to be in the accessKey property and the AWS secret key is expected to be in " +
				"the secretKey property.",
		},
	}
}

func outputFlags() []cli.Flag {
	return append(inputFlags(),
		&cli.StringFlag{
			Name:  "out",
			Usage: "The output filename, must not exist, to write the keyset to or standard output if not specified",
		},
		&cli.StringFlag{
			Name:  "out-format",
			Usage: "The output format: json or binary (case-insensitive).",
			Value: "json",
		},
	)
}

func keyIDFlags() []cli.Flag {
	return append(outputFlags(),
		&cli.UintFlag{
			Name:  "key-id",
			Usage: "The target key id",
		},
	)
}

func createFlags() []cli.Flag {
	return append(outputFlags(),
		&cli.StringFlag{
			Name:  "key-template",
			Usage: "The key template name. Run list-key-templates to get supported names.",
			Value: "AES128_GCM",
		},
	)
}

func addKeyFlags() []cli.Flag {
	return append(outputFlags(),
		&cli.StringFlag{
			Name:  "key-template",
			Usage: "The key template name. Run list-key-templates to get supported names.",
		},
	)
}

// newCliOpts reads the shared flags out of the parsed subcommand into the
// options struct used by the validation and run functions.
func newCliOpts(cmd *cli.Command) *cliOpts {
	return &cliOpts{
		in:           cmd.String("in"),
		inFormat:     cmd.String("in-format"),
		masterKeyURI: cmd.String("master-key-uri"),
		credential:   cmd.String("credential"),

		out:       cmd.String("out"),
		outFormat: cmd.String("out-format"),

		keyID: cmd.Uint("key-id"),

		keyTemplate: cmd.String("key-template"),
	}
}

func getOutputFile(opts *cliOpts) (io.Writer, func(), error) {
	if opts.out == "" {
		return os.Stdout, func() {}, nil
	}

	f, err := os.OpenFile(opts.out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening output file: %v", err)
	}

	return f, func() {
		f.Close()
	}, nil
}

func getInputFile(opts *cliOpts) (io.Reader, func(), error) {
	if opts.in == "" {
		return os.Stdin, func() {}, nil
	}

	f, err := os.Open(opts.in)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening input file: %v", err)
	}

	return f, func() {
		f.Close()
	}, nil
}

func writeKeyHandle(opts *cliOpts, kh *keyset.Handle, masterAEAD tink.AEAD) error {
	f, close, err := getOutputFile(opts)
	if err != nil {
		return err
	}
	defer close()

	var w keyset.Writer
	if opts.outFormat == "json" {
		w = keyset.NewJSONWriter(f)
	} else {
		w = keyset.NewBinaryWriter(f)
	}

	if err := kh.Write(w, masterAEAD); err != nil {
		return fmt.Errorf("failed to write keyset: %v", err)
	}

	return nil
}

func readKeyHandle(opts *cliOpts, masterAEAD tink.AEAD) (*keyset.Handle, error) {
	f, close, err := getInputFile(opts)
	if err != nil {
		return nil, err
	}
	defer close()

	var r keyset.Reader
	if opts.inFormat == "json" {
		r = keyset.NewJSONReader(f)
	} else {
		r = keyset.NewBinaryReader(f)
	}

	kh, err := keyset.Read(r, masterAEAD)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyset: %v", err)
	}

	return kh, nil
}

func updateKeyset(opts *cliOpts, update func(manager *keyset.Manager) error) error {
	masterAEAD, err := getKEK(opts.masterKeyURI, opts.credential)
	if err != nil {
		return fmt.Errorf("failed to get KEK: %v", err)
	}

	kh, err := readKeyHandle(opts, masterAEAD)
	if err != nil {
		return err
	}

	m := keyset.NewManagerFromHandle(kh)

	if err := update(m); err != nil {
		return fmt.Errorf("failed to update keyset: %v", err)
	}

	kh, err = m.Handle()
	if err != nil {
		return fmt.Errorf("failed to get updated key handle: %v", err)
	}

	return writeKeyHandle(opts, kh, masterAEAD)
}
