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

## Usage

### Command-line Flags

- `-client`: Set to true if running as a client.
- `-server`: Set to true if running as a server.
- `-target-port`: Target port number.
- `-target-domain`: Target domain.
- `-listen-port`: Listen port number.
- `-measurements`: Path to JSON Attestation Measurement file.

### Example Usage

#### Building the client

```bash
go build
```

### Running the server

To run the application as a server, execute the following command:

```bash
sudo ./cvm-reverse-proxy -server -target-domain=<target-domain> -target-port=<target-port> -listen-port=<listen-port>
```

Replace `<target-domain>`, `<target-port>` and `<listen-port>` with appropriate values.

#### Running as client

To run the application as a client, execute the following command:

```bash
./cvm-reverse-proxy -client -target-domain=<target-domain> -target-port=<target-port> -listen-port=<listen-port> -measurements=<path-to-measurements-file>
```

Replace `<target-domain>`, `<target-port>`, `<listen-port>`, and `<path-to-measurements-file>` with appropriate values.

You can start with an empty measurements file (i.e. `echo "{}" > measurements.json`)


---

## Notes

- Files in `internal/` are copied from https://github.com/edgelesssys/constellation