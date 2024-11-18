package main

//
// Make a HTTP GET request over a TEE-attested connection (to a server with aTLS support),
// and print the verified measurements and the response payload.
//
// Currently only works for Azure TDX but is straight-forward to expand.
//
// Usage:
//
//   go run cmd/attested-get/main.go --addr=https://instance_ip:port
//
// Can also save the verified measurements and the response body to files:
//
//   go run cmd/attested-get/main.go --addr=https://instance_ip:port --out-measurements=measurements.json --out-response=response.txt
//

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/flashbots/cvm-reverse-proxy/common"
	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
<<<<<<< HEAD
	azure_tdx "github.com/flashbots/cvm-reverse-proxy/internal/attestation/azure/tdx"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/measurements"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
	"github.com/flashbots/cvm-reverse-proxy/internal/config"
=======
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
>>>>>>> e8bf2544 (rename to attested-get)
	"github.com/flashbots/cvm-reverse-proxy/proxy"
	"github.com/urfave/cli/v2" // imports as package "cli"
)

var flags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:  "addr",
		Value: "https://localhost:7936",
		Usage: "TEE server address",
	},
	&cli.StringFlag{
		Name:  "out-measurements",
		Value: "",
		Usage: "Output file for the measurements",
	},
	&cli.StringFlag{
		Name:  "out-response",
		Value: "",
		Usage: "Output file for the response payload",
	},
<<<<<<< HEAD
	&cli.StringFlag{
		Name:  "attestation-type", // TODO: Add support for other attestation types
		Value: string(proxy.AttestationAzureTDX),
		Usage: "type of attestation to present (currently only azure-tdx)",
	},
=======
>>>>>>> e8bf2544 (rename to attested-get)
	&cli.BoolFlag{
		Name:  "log-debug",
		Value: false,
		Usage: "log debug messages",
	},
}

func main() {
	app := &cli.App{
		Name:   "attested-get",
		Usage:  "Get verified measurements",
		Flags:  flags,
		Action: runClient,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runClient(cCtx *cli.Context) (err error) {
	logDebug := cCtx.Bool("log-debug")
	addr := cCtx.String("addr")
	outMeasurements := cCtx.String("out-measurements")
	outResponse := cCtx.String("out-response")
	attestationTypeStr := cCtx.String("attestation-type")

	// Setup logging
	log := common.SetupLogger(&common.LoggingOpts{
		Debug:   logDebug,
		JSON:    false,
		Service: "attested-get",
		Version: common.Version,
	})

	if !strings.HasPrefix(addr, "https://") {
		return errors.New("address needs to start with https://")
	}

	// Create validators based on the attestation type
	attestationType, err := proxy.ParseAttestationType(attestationTypeStr)
	if err != nil {
		log.With("attestation-type", attestationType).Error("invalid attestation-type passed, see --help")
		return err
	}

	var validators []atls.Validator
	switch attestationType {
	case proxy.AttestationAzureTDX:
		// Prepare an azure-tdx validator without any required measurements
		attConfig := config.DefaultForAzureTDX()
		attConfig.SetMeasurements(measurements.M{})
		validator := azure_tdx.NewValidator(attConfig, proxy.AttestationLogger{Log: log})
		validators = append(validators, validator)
	default:
		log.Error("currently only azure-tdx attestation is supported")
		return errors.New("currently only azure-tdx attestation is supported")
	}

	// Prepare aTLS stuff
	issuer, err := proxy.CreateAttestationIssuer(log, proxy.AttestationAzureTDX)
	if err != nil {
		log.Error("could not create attestation issuer", "err", err)
		return err
	}

	// Create the (a)TLS config
	tlsConfig, err := atls.CreateAttestationClientTLSConfig(issuer, validators)
	if err != nil {
		log.Error("could not create atls config", "err", err)
		return err
	}

	// Prepare the client
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
	}}

	// Execute the GET request
	log.Info("Executing attested GET request to " + addr + " ...")
	resp, err := client.Get(addr)
	if err != nil {
		return err
	}

	// Extract the aTLS variant and measurements from the TLS connection
	atlsVariant, extractedMeasurements, err := proxy.GetMeasurementsFromTLS(resp.TLS.PeerCertificates, []asn1.ObjectIdentifier{variant.AzureTDX{}.OID()})
	if err != nil {
		log.Error("Error in getMeasurementsFromTLS", "err", err)
		return err
	}

	measurementsInHeaderFormat := make(map[uint32]string, len(extractedMeasurements))
	for pcr, value := range extractedMeasurements {
		measurementsInHeaderFormat[pcr] = hex.EncodeToString(value)
	}

	marshaledPcrs, err := json.MarshalIndent(measurementsInHeaderFormat, "", "    ")
	if err != nil {
		return errors.New("could not marshal measurement extracted from tls extension")
	}

	log.Info(fmt.Sprintf("Measurements for %s with %d entries:", atlsVariant.String(), len(measurementsInHeaderFormat)))
	fmt.Println(string(marshaledPcrs))
	if outMeasurements != "" {
		if err := os.WriteFile(outMeasurements, marshaledPcrs, 0o644); err != nil {
			return err
		}
	}

	// Print the response body
	msg, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	log.Info(fmt.Sprintf("Response body with %d bytes:", len(msg)))
	fmt.Println(string(msg))
	if outResponse != "" {
		if err := os.WriteFile(outResponse, msg, 0o644); err != nil {
			return err
		}
	}

	return nil
}
