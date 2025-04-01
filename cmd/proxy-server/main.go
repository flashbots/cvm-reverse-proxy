package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flashbots/cvm-reverse-proxy/common"
	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	"github.com/flashbots/cvm-reverse-proxy/proxy"
	"github.com/flashbots/cvm-reverse-proxy/tdx"
	"github.com/urfave/cli/v2" // imports as package "cli"
)

var flags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:    "listen-addr",
		EnvVars: []string{"LISTEN_ADDR"},
		Value:   "127.0.0.1:8080",
		Usage:   "address to listen on",
	},
	&cli.StringFlag{
		Name:    "listen-addr-healthcheck",
		EnvVars: []string{"LISTEN_ADDR_HEALTHCHECK"},
		Value:   "",
		Usage:   "address to listen on for health checks",
	},
	&cli.StringFlag{
		Name:    "target-addr",
		EnvVars: []string{"TARGET_ADDR"},
		Value:   "https://localhost:80",
		Usage:   "address to proxy requests to",
	},
	&cli.StringFlag{
		Name:    "server-attestation-type",
		EnvVars: []string{"SERVER_ATTESTATION_TYPE"},
		Value:   string(proxy.AttestationAuto),
		Usage:   "type of attestation to present (" + proxy.AvailableAttestationTypes + "). Set to 'dummy' to connect to a remote tdx quote provider. Defaults to automatic detection.",
	},
	&cli.StringFlag{
		Name:    "tls-certificate-path",
		EnvVars: []string{"TLS_CERTIFICATE_PATH"},
		Usage:   "Path to TLS certificate file (PEM). Only valid for --server-attestation-type=none and with --tls-private-key-path",
	},
	&cli.StringFlag{
		Name:    "tls-private-key-path",
		EnvVars: []string{"TLS_PRIVATE_KEY_PATH"},
		Usage:   "Path to private key file for the certificate. Only valid with --tls-certificate-path",
	},
	&cli.StringFlag{
		Name:  "client-attestation-type",
		Usage: "Deprecated and not used. Client attestation types are set via the measurements file.",
	},
	&cli.StringFlag{
		Name:    "client-measurements",
		EnvVars: []string{"CLIENT_MEASUREMENTS"},
		Usage:   "optional path to JSON measurements enforced on the client",
	},
	&cli.BoolFlag{
		Name:    "log-json",
		EnvVars: []string{"LOG_JSON"},
		Value:   false,
		Usage:   "log in JSON format",
	},
	&cli.BoolFlag{
		Name:    "log-debug",
		EnvVars: []string{"LOG_DEBUG"},
		Value:   true,
		Usage:   "log debug messages",
	},
	&cli.BoolFlag{
		Name:    "log-dcap-quote",
		EnvVars: []string{"LOG_DCAP_QUOTE"},
		Value:   false,
		Usage:   "log dcap quotes to folder quotes/",
	},
	&cli.StringFlag{
		Name:    "dev-dummy-dcap",
		EnvVars: []string{"DEV_DUMMY_DCAP"},
		Usage:   "URL of the remote dummy DCAP service. Only with --server-attestation-type dummy.",
	},
}

var log *slog.Logger

func main() {
	app := &cli.App{
		Name:   "proxy-server",
		Usage:  "Serve API, and metrics",
		Flags:  flags,
		Action: runServer,
	}

	if err := app.Run(os.Args); err != nil {
		if log != nil {
			log.Error("error running app", "err", err)
		} else {
			panic(err)
		}
	}
}

func runServer(cCtx *cli.Context) error {
	listenAddr := cCtx.String("listen-addr")
	targetAddr := cCtx.String("target-addr")
	clientMeasurements := cCtx.String("client-measurements")
	logJSON := cCtx.Bool("log-json")
	logDebug := cCtx.Bool("log-debug")
	tdx.SetLogDcapQuote(cCtx.Bool("log-dcap-quote"))

	serverAttestationTypeFlag := cCtx.String("server-attestation-type")
	devDummyDcapURL := cCtx.String("dev-dummy-dcap")

	certFile := cCtx.String("tls-certificate-path")
	keyFile := cCtx.String("tls-private-key-path")

	log = common.SetupLogger(&common.LoggingOpts{
		Debug:   logDebug,
		JSON:    logJSON,
		Service: "proxy-server",
		Version: common.Version,
	})

	if cCtx.String("client-attestation-type") != "" {
		log.Warn("DEPRECATED: --client-attestation-type is deprecated and will be removed in a future version")
	}

	useRegularTLS := certFile != "" || keyFile != ""
	if serverAttestationTypeFlag != "none" && useRegularTLS {
		return errors.New("invalid combination of --tls-certificate-path, --tls-private-key-path and --server-attestation-type flags passed (only 'none' is allowed)")
	}

	if useRegularTLS && (certFile == "" || keyFile == "") {
		return errors.New("not all of --tls-certificate-path and --tls-private-key-path specified")
	}

	validators, err := proxy.CreateAttestationValidatorsFromFile(log, clientMeasurements)
	if err != nil {
		log.Error("could not create attestation validators from file", "err", err)
		return err
	}

	var issuer atls.Issuer

	if serverAttestationTypeFlag == "dummy" && devDummyDcapURL == "" {
		return errors.New("server attestation type set to dummy but url not provided")
	} else if serverAttestationTypeFlag != "dummy" && devDummyDcapURL != "" {
		return errors.New("server attestation type not set to dummy but url provided")
	} else if serverAttestationTypeFlag == "dummy" && devDummyDcapURL != "" {
		issuer = tdx.NewRemoteIssuer(tdx.DefaultRemoteQuoteProviderConfig(devDummyDcapURL), log)
	} else {
		serverAttestationType, err := proxy.ParseAttestationType(serverAttestationTypeFlag)
		if err != nil {
			log.With("attestation-type", cCtx.String("server-attestation-type")).Error("invalid server-attestation-type passed, see --help")
			return err
		}

		issuer, err = proxy.CreateAttestationIssuer(log, serverAttestationType)
		if err != nil {
			log.Error("could not create attestation issuer", "err", err)
			return err
		}
	}

	proxyHandler := proxy.NewProxy(log, targetAddr, validators)

	confTLS, err := atls.CreateAttestationServerTLSConfig(issuer, validators)
	if err != nil {
		panic(err)
	}

	if useRegularTLS {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Error("could not load tls key pair", "err", err)
			return err
		}

		atlsGetConfigForClient := confTLS.GetConfigForClient

		confTLS = &tls.Config{
			GetConfigForClient: func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
				ogClientConfig, err := atlsGetConfigForClient(clientHello)
				if err != nil {
					return ogClientConfig, err
				}

				// Note: we don't have to copy the certificate because it's always created per request
				ogClientConfig.Certificates = []tls.Certificate{cert}
				ogClientConfig.GetCertificate = nil
				return ogClientConfig, nil
			},
		}
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

	// Start the health check server
	listenAddrHealthCheck := cCtx.String("listen-addr-healthcheck")
	if listenAddrHealthCheck != "" {
		go startHealthCheckServer(listenAddrHealthCheck)
	}

	log.With("listenAddr", listenAddr).Info("Starting proxy server")

	err = server.Serve(tlsListener)
	if err != nil {
		log.Error("stopping proxy", "server error", err)
		return err
	}

	return nil
}

func startHealthCheckServer(listenAddr string) {
	log.With("healthCheckListenAddr", listenAddr).Info("Starting health check server")
	healthCheckServer := &http.Server{
		Addr: listenAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	err := healthCheckServer.ListenAndServe()
	if err != nil {
		log.Error("could not start health check server", "err", err)
	}
}
