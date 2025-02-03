package main

import (
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/flashbots/cvm-reverse-proxy/common"
	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	"github.com/flashbots/cvm-reverse-proxy/proxy"
	"github.com/flashbots/cvm-reverse-proxy/tdx"
	"github.com/urfave/cli/v2" // imports as package "cli"
)

var flags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:  "listen-addr",
		Value: "127.0.0.1:8080",
		Usage: "address to listen on",
	},
	&cli.StringFlag{
		Name:  "target-addr",
		Value: "https://localhost:80",
		Usage: "address to proxy requests to",
	},
	&cli.StringFlag{
		Name:  "server-attestation-type",
		Value: string(proxy.AttestationAzureTDX),
		Usage: "type of attestation to expect and verify (" + proxy.AvailableAttestationTypes + ")",
	},
	&cli.StringFlag{
		Name:  "server-measurements",
		Usage: "optional path to JSON measurements enforced on the server",
	},
	&cli.BoolFlag{
		Name:  "verify-tls",
		Value: false,
		Usage: "verify server's TLS certificate instead of server's attestation. Only valid for server-attestation-type=none.",
	},
	&cli.StringFlag{
		Name:  "tls-ca-certificate",
		Usage: "additional CA certificate to verify against (PEM) [default=no additional TLS certs]. Only valid with --verify-tls.",
	},
	&cli.StringFlag{
		Name:  "client-attestation-type",
		Value: "auto",
		Usage: "type of attestation to present (" + proxy.AvailableAttestationTypes + "). If not set, automatically detected.",
	},
	&cli.BoolFlag{
		Name:  "log-json",
		Value: false,
		Usage: "log in JSON format",
	},
	&cli.BoolFlag{
		Name:  "log-debug",
		Value: true,
		Usage: "log debug messages",
	},
	&cli.BoolFlag{
		Name:    "log-dcap-quote",
		EnvVars: []string{"LOG_DCAP_QUOTE"},
		Value:   false,
		Usage:   "log dcap quotes to folder quotes/",
	},
}

func main() {
	app := &cli.App{
		Name:   "proxy-client",
		Usage:  "Serve API, and metrics",
		Flags:  flags,
		Action: runClient,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runClient(cCtx *cli.Context) error {
	listenAddr := cCtx.String("listen-addr")
	targetAddr := cCtx.String("target-addr")
	serverMeasurements := cCtx.String("server-measurements")
	logJSON := cCtx.Bool("log-json")
	logDebug := cCtx.Bool("log-debug")
	tdx.SetLogDcapQuote(cCtx.Bool("log-dcap-quote"))

	verifyTLS := cCtx.Bool("verify-tls")

	log := common.SetupLogger(&common.LoggingOpts{
		Debug:   logDebug,
		JSON:    logJSON,
		Service: "proxy-client",
		Version: common.Version,
	})

	if cCtx.String("server-attestation-type") != "none" && verifyTLS {
		log.Error("invalid combination of --verify-tls and --server-attestation-type passed (only 'none' is allowed)")
		return errors.New("invalid combination of --verify-tls and --server-attestation-type passed (only 'none' is allowed)")
	}

	clientAttestationType, err := proxy.ParseAttestationType(cCtx.String("client-attestation-type"))
	if err != nil {
		log.With("attestation-type", cCtx.String("client-attestation-type")).Error("invalid client-attestation-type passed, see --help")
		return err
	}

	serverAttestationType, err := proxy.ParseAttestationType(cCtx.String("server-attestation-type"))
	if err != nil {
		log.With("attestation-type", cCtx.String("server-attestation-type")).Error("invalid server-attestation-type passed, see --help")
		return err
	}

	issuer, err := proxy.CreateAttestationIssuer(log, clientAttestationType)
	if err != nil {
		log.Error("could not create attestation issuer", "err", err)
		return err
	}

	validators, err := proxy.CreateAttestationValidators(log, serverAttestationType, serverMeasurements)
	if err != nil {
		log.Error("could not create attestation validators", "err", err)
		return err
	}

	tlsConfig, err := atls.CreateAttestationClientTLSConfig(issuer, validators)
	if err != nil {
		log.Error("could not create atls config", "err", err)
		return err
	}

	if verifyTLS {
		tlsConfig.InsecureSkipVerify = false
		tlsConfig.ServerName = ""
	}

	if additionalTLSCA := cCtx.String("tls-ca-certificate"); additionalTLSCA != "" {
		if !verifyTLS {
			log.Error("--tls-ca-certificate specified but --verify-tls is not, refusing to continue")
			return errors.New("--tls-ca-certificate specified but --verify-tls is not, refusing to continue")
		}

		certData, err := os.ReadFile(additionalTLSCA)
		if err != nil {
			log.Error("could not read tls ca certificate data", "err", err)
			return err
		}

		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(certData)
		if !ok {
			log.Error("invalid certificate received", "cert", string(certData))
			return errors.New("invalid certificate")
		}

		tlsConfig.RootCAs = roots
	}

	proxyHandler := proxy.NewProxy(log, targetAddr, validators).WithTransport(&http.Transport{TLSClientConfig: tlsConfig})

	log.With("listenAddr", listenAddr).Info("Starting proxy client")
	err = http.ListenAndServe(listenAddr, proxyHandler)
	if err != nil {
		log.Error("stopping proxy", "server error", err)
		return err
	}

	return nil
}
