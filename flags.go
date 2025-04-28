package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type cliOpts struct {
	in           string
	inFormat     string
	masterKeyURI string
	credential   string

	out       string
	outFormat string

	keyID uint

	keyTemplate string
}

func registerInputOpts(cmd *flag.FlagSet, opts *cliOpts) {
	cmd.StringVar(&opts.in, "in", "", "The input filename, must exist, to read the keyset from or standard input if not specified")
	cmd.StringVar(&opts.inFormat, "in-format", "json", "The input format: json or binary (case-insensitive).")
	cmd.StringVar(&opts.masterKeyURI, "master-key-uri", "", "The keyset might be encrypted with a master key in Google Cloud KMS or AWS KMS. "+
		"This option specifies the URI of the master key. "+
		"If missing, read or write cleartext keysets. "+
		"Google Cloud KMS keys have this format: "+
		"gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*. "+
		"AWS KMS keys have this format: "+
		"aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>.")
	cmd.StringVar(&opts.credential, "credential", "", "If --master-key-uri is specified, this option specifies the credentials file path. "+
		"Must exist if specified. If missing, use default credentials. "+
		"Google Cloud credentials are service account JSON files. "+
		"AWS credentials are properties files with the AWS access key ID is expected "+
		"to be in the accessKey property and the AWS secret key is expected to be in "+
		"the secretKey property.")
}

func validateInputOpts(opts *cliOpts) error {
	opts.inFormat = strings.ToLower(opts.inFormat)
	if opts.inFormat != "json" && opts.inFormat != "binary" {
		return fmt.Errorf("unsupported input format: %s", opts.inFormat)
	}

	// validate the input file exists
	if opts.in != "" {
		info, err := os.Stat(opts.in)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("input file does not exist: %s", opts.in)
			}
			return fmt.Errorf("error reading input file: %v", err)

		}
		if info.IsDir() {
			return fmt.Errorf("input file is a directory: %s", opts.in)
		}
	}

	if opts.masterKeyURI == "" && opts.credential != "" {
		return fmt.Errorf("credentials should be provided only if the master key is provided")
	}

	if opts.credential != "" {
		info, err := os.Stat(opts.credential)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("credential file does not exist: %s", opts.credential)
			}
			return fmt.Errorf("error reading credential file: %v", err)
		}
		if info.IsDir() {
			return fmt.Errorf("credential file is a directory: %s", opts.credential)
		}
	}

	return nil
}

func registerOutputOpts(cmd *flag.FlagSet, opts *cliOpts) {
	registerInputOpts(cmd, opts)

	cmd.StringVar(&opts.out, "out", "", "The output filename, must not exist, to write the keyset to or standard output if not specified")
	cmd.StringVar(&opts.outFormat, "out-format", "json", "The output format: json or binary (case-insensitive).")
}

func validateOutputOpts(opts *cliOpts) error {
	if err := validateInputOpts(opts); err != nil {
		return err
	}

	opts.outFormat = strings.ToLower(opts.outFormat)
	if opts.outFormat != "json" && opts.outFormat != "binary" {
		return fmt.Errorf("unsupported output format: %s", opts.outFormat)
	}

	if opts.out != "" {
		// validate the output file does not exist
		if _, err := os.Stat(opts.out); err == nil {
			return fmt.Errorf("output file already exists: %s", opts.out)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("error reading output file: %v", err)
		}
	}

	return nil
}

func registerKeyIDOpts(cmd *flag.FlagSet, opts *cliOpts) {
	registerOutputOpts(cmd, opts)

	cmd.UintVar(&opts.keyID, "key-id", 0, "The target key id")
}

func validateKeyIDOpts(opts *cliOpts) error {
	if err := validateOutputOpts(opts); err != nil {
		return err
	}
	if opts.keyID == 0 {
		return fmt.Errorf("flag key-id is required")
	}
	return nil
}

func registerCreateKeysetOpts(cmd *flag.FlagSet, opts *cliOpts) {
	registerOutputOpts(cmd, opts)

	cmd.StringVar(&opts.keyTemplate, "key-template", "AES128_GCM", "The key template name. Run list-key-templates to get supported names.")
}

func validateCreateKeysetOpts(opts *cliOpts) error {
	if err := validateOutputOpts(opts); err != nil {
		return err
	}

	_, ok := supportedTemplates[opts.keyTemplate]
	if !ok {
		return fmt.Errorf("unsupported key template: %s", opts.keyTemplate)
	}

	return nil
}

func registerAddOpts(cmd *flag.FlagSet, opts *cliOpts) {
	registerOutputOpts(cmd, opts)

	cmd.StringVar(&opts.keyTemplate, "key-template", "", "The key template name. Run list-key-templates to get supported names.")
}

func validateAddOpts(opts *cliOpts) error {
	if err := validateOutputOpts(opts); err != nil {
		return err
	}

	if opts.keyTemplate == "" {
		return nil
	}

	_, ok := supportedTemplates[opts.keyTemplate]
	if !ok {
		return fmt.Errorf("unsupported key template: %s", opts.keyTemplate)
	}

	return nil
}
