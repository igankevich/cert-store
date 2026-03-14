[![Crates.io Version](https://img.shields.io/crates/v/cert-store)](https://crates.io/crates/cert-store)
[![Docs](https://docs.rs/cert-store/badge.svg)](https://docs.rs/cert-store)
[![dependency status](https://deps.rs/repo/github/igankevich/cert-store/status.svg)](https://deps.rs/repo/github/igankevich/cert-store)

CLI-based certificate store. Inspired by [Password Store](https://www.passwordstore.org/).

This tool generates keys and SSL certificates and stores them locally in a git repository.
Keys are encrypted with GPG and can be safely transferred to a remote git repository.
The main use case is to manage certificates for domains in a home network
without relying on centralized certificate authorities and domain registrars.

Required CLI tools: `git`, `openssl` (for exporting certificates and keys in PKCS12 format), `xclip` (for clipboard).

## Installation

```bash
cargo install cert-store
```


## Usage

### Initializing the store, adding certificates

```bash
# Initialize the store.
# 
# This command will initialize the store in ~/.cert-store and generate root certificate.
cert init

# Generate server key and certificate for localhost.
cert insert -t server localhost 127.0.0.1 ::1

# Generate client key and certificate.
cert insert -t client myphone

# Push all certificate to the git server.
cert git push
```


### TLS with Caddy

```bash
# Generate server key and certificate.
#
# ollama.internal - a domain name
cert insert -t server ollama.internal

# Export server certificate and key in PEM format.
cert export ollama.intenal /etc/caddy

# Simple Caddy configuration.
cat >/etc/caddy/Caddyfile <<'EOF'
ollama.internal {
    tls /etc/caddy/ollama.internal.crt /etc/caddy/ollama.internal.key
    reverse_proxy / 127.0.0.1:11434
}
EOF

# Export root certificate in PEM format.
#
# Default root certificate uses your username as the common name.
cert show-cert "$USER" >/tmp/ca.crt

# Now import /tmp/ca.crt in your browser as trusted certificate authority.
# 
# Below is an example for curl.
curl --cacert /tmp/ca.crt https://ollama.internal/
```

### Mutual TLS (mTLS) with Caddy

```bash
# Generate server key and certificate.
#
# ollama.internal - a domain name
cert insert -t server ollama.internal

# Generate client key and certificate.
#
# desktop - certificate name; can be any name, but here we use device name for simplicity
cert insert -t client desktop

# Export server certificate and key in PEM format.
cert export ollama.intenal /etc/caddy

# Simple Caddy configuration.
cat >/etc/caddy/Caddyfile <<'EOF'
ollama.internal {
    tls /etc/caddy/ollama.internal.crt /etc/caddy/ollama.internal.key {
          client_auth {
              trust_pool file {
                  pem_file /etc/caddy/ca.crt
              }
          }
    }
    reverse_proxy / 127.0.0.1:11434
}
EOF

# Export root certificate in PEM format.
#
# Default root certificate uses your username as the common name.
cert show-cert "$USER" >/etc/caddy/ca.crt

# Export client certificate and key in PKCS12 format.
cert export -t pkcs12 desktop /dev/shm

# Now import /etc/caddy/ca.crt in your browser as trusted certificate authority.
# Then import /dev/shm/desktop.p12 in your brwoser as a client certificate.
# 
# Below is an example for curl.
#
# With curl it is easier to use PEM client certificates, so we export in this format.
# Beware that the key is not encrypted when exported as PEM.
cert export desktop /dev/shm
curl --cacert /etc/caddy/ca.crt --key /dev/shm/desktop.key --cert /dev/shm/desktop.cert \
    https://ollama.internal/
```
