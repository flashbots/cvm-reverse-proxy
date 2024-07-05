package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/konvera/geth-sev/constellation/atls"
	azure_tdx "github.com/konvera/geth-sev/constellation/attestation/azure/tdx"
	baremetal_tdx "github.com/konvera/geth-sev/constellation/attestation/tdx"
	"github.com/konvera/geth-sev/constellation/config"

	"cvm-reverse-proxy/common"
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
		Name:  "measurements",
		Value: "measurements.json",
		Usage: "path to JSON measurements",
	},
	&cli.StringFlag{
		Name:  "attestation-type",
		Value: "azure",
		Usage: "type of attestation to present (azure-tdx, baremetal-tdx) [azure-tdx]",
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
		Action: client_side_tls_termination,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func client_side_tls_termination(cCtx *cli.Context) error {
	listenAddr := cCtx.String("listen-addr")
	targetAddr := cCtx.String("target-addr")
	measurementsPath := cCtx.String("measurements")
	logJSON := cCtx.Bool("log-json")
	logDebug := cCtx.Bool("log-debug")
	logService := cCtx.String("cvm-azure-tdx-client")

	log := common.SetupLogger(&common.LoggingOpts{
		Debug:   logDebug,
		JSON:    logJSON,
		Service: logService,
		Version: common.Version,
	})

	// Read the measurements file
	jsonMeasurements, err := os.ReadFile(measurementsPath)
	if err != nil {
		log.Error("could not read measurements", "err", err)
		return err
	}

	attConfig := config.DefaultForAzureTDX()
	err = json.Unmarshal(jsonMeasurements, &attConfig.Measurements)
	if err != nil {
		log.Error("could not decode measurements", "err", err)
		return err
	}

	validators := []atls.Validator{azure_tdx.NewValidator(attConfig, proxy.AttestationLogger{})}
	tlsConfig, err := atls.CreateAttestationClientTLSConfig(nil, validators)
	if err != nil {
		log.Error("could not create atls config", "err", err)
		return err
	}

	proxy := proxy.NewProxy(targetAddr).WithTransport(&http.Transport{TLSClientConfig: tlsConfig})

	// Create attested TLS config
	var issuer atls.Issuer
	attestationType := cCtx.String("attestation-type")
	switch attestationType {
	case "azure-tdx":
		issuer = azure_tdx.NewIssuer(nil)
	case "baremetal-tdx":
		issuer = baremetal_tdx.NewIssuer(nil)
	default:
		log.With("attestation-type", attestationType).Error("invalid attestation-type passed, must be one of [azure-tdx, baremetal-tdx]")
		return errors.New("invalid attestation-type passed in")
	}

	confTLS, err := atls.CreateAttestationServerTLSConfig(issuer, nil)
	if err != nil {
		panic(err)
	}

	// Create an HTTP server
	server := &http.Server{
		Addr:      listenAddr,
		Handler:   proxy,
		TLSConfig: confTLS,
	}

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)
	// Shutdown server once termination signal is received

	go func() {
		<-exit
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.With("listenAddr", listenAddr).Info("about to start proxy")
	err = http.ListenAndServe(listenAddr, proxy)
	if err != nil {
		log.Error("stopping proxy", "server error", err)
		return err
	}

	return nil
}
