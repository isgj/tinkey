package main

import (
	"fmt"
	"io"
	"os"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

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
