package main

import (
	"crypto/x509"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/flashbots/cvm-reverse-proxy/common"
	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	"github.com/flashbots/cvm-reverse-proxy/multimeasurements"
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
		Usage: "Deprecated and not used. Server attestation types are set via the measurements file.",
	},
	&cli.StringFlag{
		Name:  "server-measurements",
		Usage: "optional path to JSON measurements enforced on the server",
	},
	&cli.BoolFlag{
		Name:  "verify-tls",
		Value: false,
		Usage: "verify server's TLS certificate instead of server's attestation. Only valid when not specifying measurements.",
	},
	&cli.StringFlag{
		Name:  "tls-ca-certificate",
		Usage: "additional CA certificate to verify against (PEM) [default=no additional TLS certs]. Only valid with --verify-tls.",
	},
	&cli.StringFlag{
		Name:  "client-attestation-type",
		Value: string(proxy.AttestationNone),
		Usage: "type of attestation to present (" + proxy.AvailableAttestationTypes + ").",
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

type ClientConfig struct {
	ListenAddr            string `json:"listen_addr"`
	TargetAddr            string `json:"target_addr"`
	ServerMeasurements    string `json:"server_measurements"`
	VerifyTLS             bool   `json:"verify_tls"`
	TLSCACertificate      string `json:"tls_ca_certificate"`
	ClientAttestationType string `json:"client_attestation_type"`
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
	config := ClientConfig{
		ListenAddr:            cCtx.String("listen-addr"),
		TargetAddr:            cCtx.String("target-addr"),
		ServerMeasurements:    cCtx.String("server-measurements"),
		VerifyTLS:             cCtx.Bool("verify-tls"),
		TLSCACertificate:      cCtx.String("tls-ca-certificate"),
		ClientAttestationType: cCtx.String("client-attestation-type"),
	}

	log := common.SetupLogger(&common.LoggingOpts{
		Debug:   cCtx.Bool("log-debug"),
		JSON:    cCtx.Bool("log-json"),
		Service: "proxy-client",
		Version: common.Version,
	})

	if cCtx.String("server-attestation-type") != "" {
		log.Warn("DEPRECATED: --server-attestation-type is deprecated and will be removed in a future version")
	}

	tdx.SetLogDcapQuote(cCtx.Bool("log-dcap-quote"))

	return runClientFromConfig(log, config)
}

func runClientFromConfig(log *slog.Logger, config ClientConfig) error {
	if config.ServerMeasurements != "" && config.VerifyTLS {
		log.Error("invalid combination of --verify-tls and --server-measurements passed (cannot add server measurements and verify default TLS at the same time)")
		return errors.New("invalid combination of --verify-tls and --server-measurements passed (cannot add server measurements and verify default TLS at the same time)")
	}

	clientAttestationType, err := proxy.ParseAttestationType(config.ClientAttestationType)
	if err != nil {
		log.With("attestation-type", config.ClientAttestationType).Error("invalid client-attestation-type passed, see --help")
		return err
	}

	issuer, err := proxy.CreateAttestationIssuer(log, clientAttestationType)
	if err != nil {
		log.Error("could not create attestation issuer", "err", err)
		return err
	}

	parsedMeasurements, err := proxy.LoadMeasurementsFromFile(log, config.ServerMeasurements)
	if err != nil {
		log.Error("could not create attestation validators from file", "err", err)
		return err
	}

	// Maps service tag (id) to list of measurements (ids). Should be passed in separately. For now assume single "default" service.
	serviceMeasurements := map[proxy.ServiceTag][]multimeasurements.MeasurementsContainer{proxy.ServiceTag("default"): parsedMeasurements}
	serviceValidators := make(map[proxy.ServiceTag][]atls.Validator)
	for service, listOfMeasurements := range serviceMeasurements {
		validators, err := proxy.CreateAttestationValidatorsFromMeasurements(log, listOfMeasurements)
		if err != nil {
			return err
		}
		serviceValidators[service] = validators
	}

	proxyByService := make(map[proxy.ServiceTag]http.HandlerFunc)
	for service, validators := range serviceValidators {
		tlsConfig, err := atls.CreateAttestationClientTLSConfig(issuer, validators)
		if err != nil {
			log.Error("could not create atls config", "err", err)
			return err
		}

		if config.VerifyTLS {
			tlsConfig.InsecureSkipVerify = false
			tlsConfig.ServerName = ""
		}

		if additionalTLSCA := config.TLSCACertificate; additionalTLSCA != "" {
			if !config.VerifyTLS {
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

		var proxyHandler http.HandlerFunc
		if config.TargetAddr == "from_header" {
			rproxyFactory := func(targetURL *url.URL) *httputil.ReverseProxy {
				rproxy := httputil.NewSingleHostReverseProxy(targetURL)
				rproxy.Transport = &http.Transport{TLSClientConfig: tlsConfig}
				return rproxy
			}
			proxyHandler = proxy.NewDynamicHostReverseProxyFromHeader(log, validators, rproxyFactory)
		} else {
			rproxy := proxy.NewSingleHostReverseProxyFromUrl(log, validators, config.TargetAddr)
			rproxy.Transport = &http.Transport{TLSClientConfig: tlsConfig}
			proxyHandler = proxy.NewProxy(log, rproxy.ServeHTTP, validators).ServeHTTP
		}
		proxyByService[service] = proxyHandler
	}

	var proxyHandler http.Handler
	if len(proxyByService) == 1 {
		for _, onlyProxy := range proxyByService {
			proxyHandler = onlyProxy
		}
	} else {
		proxyHandler = proxy.NewMultiServiceMiddleware(proxyByService)
	}

	log.With("listenAddr", config.ListenAddr).Info("Starting proxy client")
	err = http.ListenAndServe(config.ListenAddr, proxyHandler)
	if err != nil {
		log.Error("stopping proxy", "server error", err)
		return err
	}

	return nil
}
