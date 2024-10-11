# ConfidentialVM Attestation Reverse Proxy

## Overview

This application provides a reverse proxy with TLS termination, supporting confidentialVM attestation for both client and server sides. It allows for secure communication between a client and a server, with attestation verification to ensure the integrity of the communication.

## Features

- Client-side TLS termination with confidentialVM attestation verification.
- Server-side TLS termination with confidentialVM attestation verification.
- Reverse proxy functionality to forward requests between client and server.

Both the client-side and the server-side TLS termination can be separately configured to provide attestations and verify attestations.

## Limitations

- TDX support only, SEV-SNP can be added
- uses edgeless systems [constellation](https://github.com/edgelesssys/constellation) codebase to provide attestation on Azure using MAA

## Modes of operation

Server
- TCP/HTTP server with regular TLS on the server side, to allow the client to verify the server's TLS certificate.
- TCP/HTTP server with aTLS on the server side, to allow client verify the server measurement.
- TCP/HTTP server that verifies the client (via client-side aTLS certificate). The measurement is passed along to the proxy target as header. Valid for both server-side TLS and aTLS.
- TCP/HTTP server that performs mutual attestation, that is it both provides its own attestation, and verifies the client. The *client's* measurement is forwarded as a header.

Client
- Client making a request, verifying server's TLS certificate.
- Client making a request, verifying server aTLS certificate (supporting one or multiple whitelisted measurements). The *server's* measurement is returned as a header.
- Client making a request with a client-side aTLS cert.
- Client making a request mutual attestation, both verifying server aTLS and providing the client-side aTLS handshake. The *sever's* measurement is returned as a header.

---

## proxy-server

### Command line arguments

- `--listen-addr`: address to listen on (default: "127.0.0.1:8080")
- `--target-addr`: address to proxy requests to (default: "https://localhost:80")
- `--server-attestation-type`: type of attestation to present (none, azure-tdx) (default: "azure-tdx")
- `--tls-certificate-path`: Path to certificate (PEM file) to present. Only valid for --server-attestation-type=none and with `--tls-private-key-path`.
- `--tls-private-key-path`: Path to private key file for the certificate (PEM). Only valid with --tls-certificate-path.
- `--client-attestation-type`: type of attestation to expect and verify (none, azure-tdx) (default: "none")
- `--client-measurements`: optional path to JSON measurements enforced on the client
- `--log-json`: log in JSON format (default: false)
- `--log-debug`: log debug messages (default: false)
- `--log-dcap-quote`: log dcap quotes to folder quotes/ (default: false)
- `--help, -h`: show help


### Build the server

```bash
# Build the binary
make build-proxy-server

# Build the Docker image
make docker-images
```

### Run the server

```bash
# Run the binary
sudo ./build/proxy-server --listen-addr=<listen-addr> --target-addr=<target-addr> [--server-attestation-type=<server-attestation-type>] [--client-attestation-type=<client-attestation-type>] [--client-measurements=<client-measurements>]

# Run the Docker image
docker run -p 8080:8080 -e LOG_JSON=1 cvm-proxy-server
```

By default the server will present Azure TDX attestation, and you can modify that via the `--server-attestation-type` flag.
The server can be made to present a regular TLS certificate through `--tls-certificate-path` and `--tls-private-key-path` flags instead of aTLS one.

By default the server will not verify client attestations, you can change that via `--client-attestation-type` and `--client-measurements` flags. Valid for both aTLS and regular TLS.


This repository contains a [dummy http server](./cmd/dummy-server/main.go) that you can use for testing the server. Simply run `go run ./cmd/dummy-server/main.go` and point your `--target-addr=http://127.0.0.1:8085`. You can also use the sample [measurements.json](./measurements.json).


## proxy-client

### Command line arguments

- `--listen-addr`: address to listen on (default: "127.0.0.1:8080")
- `--target-addr`: address to proxy requests to (default: "https://localhost:80")
- `--server-attestation-type`: type of attestation to expect and verify (none, azure-tdx) (default: "azure-tdx")
- `--server-measurements`: optional path to JSON measurements enforced on the server
- `--verify-tls`: verify server's TLS certificate instead of server's attestation. Only valid for server-attestation-type=none.
- `--tls-ca-certificate`: additional CA certificate to verify against (PEM) [default=no additional TLS certs]. Only valid with --verify-tls.
- `--client-attestation-type`: type of attestation to present (none, azure-tdx) (default: "none")
- `--log-json`: log in JSON format (default: false)
- `--log-debug`: log debug messages (default: false)
- `--log-dcap-quote`: log dcap quotes to folder quotes/ (default: false)
- `--help, -h`: show help


#### Build the client

```bash
make build-proxy-client
```

#### Run the client

```bash
./build/proxy-client --listen-addr=<listen-addr> --target-addr=<target-addr> [--server-measurements=<server-measurements-file>] [--server-attestation-type=<server-attestation-type>] [--client-attestation-type=<client-attestation-type>]
```

By default the client will expect the server to present an Azure TDX attestation, and you can modify that via the `--server-attestation-type` and  `--server-measurements` flags.
The server can also be a regular TLS server, which you can configure with the `--verify-tls` flag, which is only valid in combination with `--server-attestation-type=none`. Non-standard CA for the server can also be configured with `--tls-ca-certificate`.

By default the client will not present client attestations, you can change that via `--client-attestation-type` flag. Valid for both aTLS and TLS server proxies.

This repository contains a sample [measurements.json](./measurements.json) file that you can use. The client will (correctly) complain about unexpected measurements that you can then correct.


## Measurements

Attestation verification requires the expected measurements which you pass through the `--{client, server}-measurements` flag.
The measurements are expected to be a JSON map, and multiple valid measurements can be provided. The verifier will attempt to verify with each of the provided measurements, and if any succeeds, the attestation is assumed valid.

The (single) validated measurement is json-marshalled and forwarded (returned in the case of client) as "X-Flashbots-Measurement" header, and the type of attestation as "X-Flashbots-Attestation-Type" header. For mapping attestation types to OIDs and issuers, see [internal/attestation/variant/variant.go](./internal/attestation/variant/variant.go).
To only validate and forward the measurement (as opposed to also authorizing the measurement against an expected one), simply provide an empty expected measurements object.

### Debugging DCAP quote issues

If logging dcap quotes to disk is enabled, issues with the respective quotes can be investigated using [github.com/google/go-tdx-guest](https://github.com/google/go-tdx-guest)'s check tool
```
git clone https://github.com/google/go-tdx-guest
cd go-tdx-guest
go build tools/check/check.go
./check -verbosity 2 -get_collateral true -in quotes/quote_received_20241010_121042.dat
```

---

## Notes

- Files in `internal/` are copied from https://github.com/edgelesssys/constellation
