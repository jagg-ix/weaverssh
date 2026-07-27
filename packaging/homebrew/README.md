# Homebrew Packaging

weaverssh Homebrew support is generated from the source-free binary archives
created by `make binary-dist`. The generated Formula installs only the released
`wv` binary and does not require a source checkout, Go, or Python on the target
machine.

Generate a local Formula from an existing archive:

```sh
make homebrew-formula \
  HOMEBREW_ARCHIVE=dist/binary/weaverssh-0.1.0-1-darwin-arm64.tar.gz
```

Generate a multi-architecture Formula for a tap by passing all release archives
and the public URL base where those archives will be uploaded:

```sh
make homebrew-formula \
  HOMEBREW_ARCHIVES="dist/binary/weaverssh-0.1.0-1-darwin-arm64.tar.gz dist/binary/weaverssh-0.1.0-1-darwin-amd64.tar.gz dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz" \
  HOMEBREW_URL_BASE=https://github.com/jagg-ix/weaverssh/releases/download/v0.1.0
```

The default output is `dist/homebrew/Formula/weaverssh.rb`. Copy that file to a
Homebrew tap repository as `Formula/weaverssh.rb`, then install with:

```sh
brew install jagg-ix/tap/weaverssh
```

For local testing without a tap:

```sh
brew install --build-from-source ./dist/homebrew/Formula/weaverssh.rb
brew test weaverssh
```
