# Tinkey Go

This is a Go port of the Java version of [Tinkey](https://github.com/tink-crypto/tink-tinkey).

## Why?

The main reason for this port is to allow users to run Tinkey without having to install Java. This makes it easier to use in environments where Java is not readily available or desired.

## Features

- [x] Key generation
- [x] Key management
- [x] Google Cloud KMS
- [ ] Amazon KMS
- [ ] All the key templates that [tinko-go](https://github.com/tink-crypto/tink-go) supports

To add:

- [ ] Test
- [ ] Use git tags and offer builds via Github CI

## Usage

```bash
go run github.com/isgj/tinkey
```

## Credits

All credits go to [tink-tinkey](https://github.com/tink-crypto/tink-tinkey) and [tink-go](https://github.com/tink-crypto/tink-go).

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.
