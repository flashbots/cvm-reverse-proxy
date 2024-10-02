package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		Usage: "type of attestation to present (" + proxy.AvailableAttestationTypes + ")",
	},
	&cli.StringFlag{
		Name:  "client-attestation-type",
		Value: string(proxy.AttestationNone),
		Usage: "type of attestation to expect and verify (" + proxy.AvailableAttestationTypes + ")",
	},
	&cli.StringFlag{
		Name:  "client-measurements",
		Usage: "optional path to JSON measurements enforced on the client",
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
		Name:   "proxy-server",
		Usage:  "Serve API, and metrics",
		Flags:  flags,
		Action: run_server,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run_server(cCtx *cli.Context) error {
	listenAddr := cCtx.String("listen-addr")
	targetAddr := cCtx.String("target-addr")
	clientMeasurements := cCtx.String("client-measurements")
	logJSON := cCtx.Bool("log-json")
	logDebug := cCtx.Bool("log-debug")

	log := common.SetupLogger(&common.LoggingOpts{
		Debug:   logDebug,
		JSON:    logJSON,
		Service: "proxy-server",
		Version: common.Version,
	})

	serverAttestationType, err := proxy.ParseAttestationType(cCtx.String("server-attestation-type"))
	if err != nil {
		log.With("attestation-type", cCtx.String("server-attestation-type")).Error("invalid server-attestation-type passed, see --help")
		return err
	}

	clientAttestationType, err := proxy.ParseAttestationType(cCtx.String("client-attestation-type"))
	if err != nil {
		log.With("attestation-type", cCtx.String("client-attestation-type")).Error("invalid client-attestation-type passed, see --help")
		return err
	}

	validators, err := proxy.CreateAttestationValidators(log, clientAttestationType, clientMeasurements)
	if err != nil {
		log.Error("could not create attestation validators", "err", err)
		return err
	}

	issuer, err := proxy.CreateAttestationIssuer(log, serverAttestationType)
	if err != nil {
		log.Error("could not create attestation issuer", "err", err)
		return err
	}

	proxyHandler := proxy.NewProxy(targetAddr, validators)

	confTLS, err := atls.CreateAttestationServerTLSConfig(issuer, validators)
	if err != nil {
		panic(err)
	}

	// Create an HTTP server
	server := &http.Server{
		Addr:      listenAddr,
		Handler:   proxyHandler,
		TLSConfig: confTLS,
	}

	// Create a TLS listener
	tlsListener, err := tls.Listen("tcp", server.Addr, confTLS)
	if err != nil {
		log.Error("could not create TLS listener", "err", err)
		return err
	}

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)
	// Shutdown server once termination signal is received

	go func() {
		<-exit
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := server.Shutdown(ctx)
		if err != nil {
			log.Error("could not cleanly shutdown", "err", err)
		}
	}()

	log.With("listenAddr", listenAddr).Info("about to start proxy")
	err = server.Serve(tlsListener)
	if err != nil {
		log.Error("stopping proxy", "server error", err)
		return err
	}

	return nil
}
