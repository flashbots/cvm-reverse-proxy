# ConfidentialVM Attestation Reverse Proxy

## Overview

This application provides a reverse proxy with TLS termination, supporting confidentialVM attestation for both client and server sides. It allows for secure communication between a client and a server, with attestation verification to ensure the integrity of the communication.

## Features

- Client-side TLS termination with confidentialVM attestation verification.
- Server-side TLS termination with confidentialVM attestation verification.
- Reverse proxy functionality to forward requests between client and server.

## Limitations

- TDX support only, SEV-SNP can be added
- uses edgeless systems [constellation](https://github.com/edgelesssys/constellation) codebase to provide attestation on Azure using MAA

## proxy-server

### Command line arguments

- `--listen-addr`: address to listen on (default: "127.0.0.1:8080")
- `--target-addr`: address to proxy requests to (default: "https://localhost:80")
- `--attestation-type`: type of attestation to present (azure-tdx, dcap-tdx) (default: "azure")
- `--client-measurements`: path to JSON measurements enforced on connecting clients
   --server-attestation-type value  type of attestation to present (none, azure-tdx, dcap-tdx) (default: "azure-tdx")
   --client-attestation-type value  type of attestation to expect and verify (none, azure-tdx, dcap-tdx) (default: "none")
   --client-measurements value      optional path to JSON measurements enforced on the client
- `--log-json`: log in JSON format (default: false)
- `--log-debug`: log debug messages (default: false)
- `--help, -h`: show help


### Build the server

```bash
make build-proxy-server
```

### Run the server

```bash
sudo ./build/proxy-server --listen-addr=<listen-addr> --target-addr=<target-addr> [--server-attestation-type=<server-attestation-type>] [--client-attestation-type=<client-attestation-type>] [--client-measurements=<client-measurements>]
```

By default the server will present Azure TDX attestation, and you can modify that via the `--server-attestation-type` flag.

By default the server will not verify client attestations, you can change that via `--client-attestation-type` and `--client-measurements` flags.


This repository contains a [dummy http server](./cmd/dummy-server/main.go) that you can use for testing the server. Simply run `go run ./cmd/dummy-server/main.go` and point your `--target-addr=http://127.0.0.1:8085`. You can also use the sample [measurements.json](./measurements.json).

## proxy-client

### Command line arguments

- `--listen-addr`: address to listen on (default: "127.0.0.1:8080")
- `--target-addr`: address to proxy requests to (default: "https://localhost:80")
- `--server-measurements`: path to JSON measurements
- `--attestation-type`: type of attestation to present (azure-tdx, dcap-tdx) (default: "azure")
   --client-attestation-type value  type of attestation to present (none, azure-tdx, dcap-tdx) (default: "none")
   --server-attestation-type value  type of attestation to expect and verify (none, azure-tdx, dcap-tdx) (default: "azure-tdx")
   --server-measurements value      optional path to JSON measurements enforced on the server
- `--log-json`: log in JSON format (default: false)
- `--log-debug`: log debug messages (default: false)
- `--help, -h`: show help


#### Build the client

```bash
make build-proxy-client
```

#### Run the client

```bash
./build/proxy-client --listen-addr=<listen-addr> --target-addr=<target-addr> --measurements=<measurements-fule> [--attestation-type=<attestation-type>]
```

By default the client will expect the server to present an Azure TDX attestation, and you can modify that via the `--server-attestation-type` and  `--server-measurements` flags.

By default the client will not present client attestations, you can change that via `--client-attestation-type` flag.

This repository contains a sample [measurements.json](./measurements.json) file that you can use. The client will (correctly) complain about unexpected measurements that you can then correct.

---

## Notes

- Files in `internal/` are copied from https://github.com/edgelesssys/constellation
