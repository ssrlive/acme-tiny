# ACME-tiny powered by Rust

This is a Rust implementation of the ACME client, which is a simple client for the ACME protocol used to obtain SSL/TLS certificates from [Let's Encrypt](https://letsencrypt.org/).

The code is translated from the [original Python version of ACME-tiny](https://github.com/diafygi/acme-tiny).


## CLI

```plaintext
acme-tiny -h

Automates getting a signed TLS certificate from Let's Encrypt using the ACME protocol.
It will need to be run on your server and have access to your private account key.
Version: 0.1.1 (beda80a 2025-03-25 01:22:36)

Usage: acme-tiny [OPTIONS] --account-key <FILE> --csr <FILE> --acme-dir <DIR>

Options:
  -a, --account-key <FILE>      path to your Let's Encrypt account private key
  -c, --csr <FILE>              path to your certificate signing request
  -d, --acme-dir <DIR>          path to the .well-known/acme-challenge/ directory
      --quiet                   suppress output except for errors
      --disable-check           disable checking if the challenge file is hosted correctly
      --directory-url <URL>     certificate authority directory url [default: https://acme-v02.api.letsencrypt.org/directory]
      --ca <URL>                DEPRECATED! USE --directory-url INSTEAD! [default: https://acme-v02.api.letsencrypt.org]
      --contact [<CONTACT>...]  Contact details (e.g. mailto:aaa@bbb.com) for your account-key
      --check-port <PORT>       what port to use when self-checking the challenge file, default is 80
  -o, --output <FILE>           Output the result to a file
  -h, --help                    Print help
  -V, --version                 Print version
  ```
