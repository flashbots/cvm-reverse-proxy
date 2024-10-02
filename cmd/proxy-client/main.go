package main

import (
	"log"
	"net/http"
	"os"

	"cvm-reverse-proxy/common"
	"cvm-reverse-proxy/internal/atls"
	"cvm-reverse-proxy/proxy"

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
	&cli.StringFlag{
		Name:  "client-attestation-type",
		Value: string(proxy.AttestationNone),
		Usage: "type of attestation to present (" + proxy.AvailableAttestationTypes + ")",
	},
	&cli.BoolFlag{
		Name:  "log-json",
		Value: false,
		Usage: "log in JSON format",
	},
	&cli.BoolFlag{
		Name:  "log-debug",
		Value: false,
		Usage: "log debug messages",
	},
}

func main() {
	app := &cli.App{
		Name:   "proxy-client",
		Usage:  "Serve API, and metrics",
		Flags:  flags,
		Action: run_client,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run_client(cCtx *cli.Context) error {
	listenAddr := cCtx.String("listen-addr")
	targetAddr := cCtx.String("target-addr")
	serverMeasurements := cCtx.String("server-measurements")
	logJSON := cCtx.Bool("log-json")
	logDebug := cCtx.Bool("log-debug")

	log := common.SetupLogger(&common.LoggingOpts{
		Debug:   logDebug,
		JSON:    logJSON,
		Service: "proxy-client",
		Version: common.Version,
	})

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

	proxyHandler := proxy.NewProxy(targetAddr, validators).WithTransport(&http.Transport{TLSClientConfig: tlsConfig})

	log.With("listenAddr", listenAddr).Info("about to start proxy")
	err = http.ListenAndServe(listenAddr, proxyHandler)
	if err != nil {
		log.Error("stopping proxy", "server error", err)
		return err
	}

	return nil
}
