package main

import (
	"fmt"
	"os"
	"strings"
)

// cliOpts carries the flag values shared by the keyset-manipulating
// subcommands. It is populated from the parsed cli.Command by newCliOpts.
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

func validateKeyIDOpts(opts *cliOpts) error {
	if err := validateOutputOpts(opts); err != nil {
		return err
	}
	if opts.keyID == 0 {
		return fmt.Errorf("flag key-id is required")
	}
	return nil
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

func validateAddOpts(opts *cliOpts) error {
	if err := validateOutputOpts(opts); err != nil {
		return err
	}

	if opts.keyTemplate == "" {
		return fmt.Errorf("flag key-template is required")
	}

	_, ok := supportedTemplates[opts.keyTemplate]
	if !ok {
		return fmt.Errorf("unsupported key template: %s", opts.keyTemplate)
	}

	return nil
}
