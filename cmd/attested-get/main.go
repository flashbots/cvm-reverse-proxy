package main

//
// Make a HTTP GET request over a TEE-attested connection (to a server with aTLS support),
// and print the verified measurements and the response payload.
//
// Currently supports Azure TDX and DCAP TDX attestation.
//
// Usage:
//
//   go run cmd/attested-get/main.go --addr=https://instance_ip:port
//
// Save the verified measurements and the response body to files:
//
//   go run cmd/attested-get/main.go \
// 		--addr=https://instance_ip:port \
// 		--out-measurements=measurements.json \
// 		--out-response=response.txt
//
// Compare the resulting measurements with a list of expected measurements:
//
//   go run cmd/attested-get/main.go \
// 		--addr=https://instance_ip:port \
// 		--expected-measurements=measurements.json
//
// Also works with an URL for expected measurements:
//
//   go run cmd/attested-get/main.go \
//		--addr=https://buildernet-01-euw.builder.flashbots.net:7936/cert \
// 		--expected-measurements=https://measurements.builder.flashbots.net
//

import (
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	azure_tcbinfo_override "github.com/flashbots/cvm-reverse-proxy/azure-tcbinfo-override"
	"github.com/flashbots/cvm-reverse-proxy/common"
	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	azure_tdx "github.com/flashbots/cvm-reverse-proxy/internal/attestation/azure/tdx"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/measurements"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
	"github.com/flashbots/cvm-reverse-proxy/internal/config"
	"github.com/flashbots/cvm-reverse-proxy/multimeasurements"
	"github.com/flashbots/cvm-reverse-proxy/proxy"
	dcap_tdx "github.com/flashbots/cvm-reverse-proxy/tdx"
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
	&cli.StringFlag{
		Name:  "attestation-type",
		Value: string(proxy.AttestationAuto),
		Usage: "type of attestation to present (auto, azure-tdx, or dcap-tdx)",
	},
	&cli.StringFlag{
		Name:  "expected-measurements",
		Value: "",
		Usage: "File or URL with known measurements (to compare against)",
	},
	&cli.BoolFlag{
		Name:    "override-azurev6-tcbinfo",
		Value:   false,
		EnvVars: []string{"OVERRIDE_AZUREV6_TCBINFO"},
		Usage:   "Allows Azure's V6 instance outdated SEAM Loader",
	},
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

// createAzureTDXValidator creates an Azure TDX validator without required measurements
func createAzureTDXValidator(log *slog.Logger, overrideAzurev6Tcbinfo bool) atls.Validator {
	attConfig := config.DefaultForAzureTDX()
	attConfig.SetMeasurements(measurements.M{})
	validator := azure_tdx.NewValidator(attConfig, proxy.AttestationLogger{Log: log})
	if overrideAzurev6Tcbinfo {
		azure_tcbinfo_override.OverrideAzureValidatorsForV6SEAMLoader(log, []atls.Validator{validator})
	}
	return validator
}

// createDCAPTDXValidator creates a DCAP TDX validator without required measurements
func createDCAPTDXValidator(log *slog.Logger) atls.Validator {
	attConfig := &config.QEMUTDX{Measurements: measurements.M{}}
	return dcap_tdx.NewValidator(attConfig, proxy.AttestationLogger{Log: log})
}

func runClient(cCtx *cli.Context) (err error) {
	logDebug := cCtx.Bool("log-debug")
	addr := cCtx.String("addr")
	outMeasurements := cCtx.String("out-measurements")
	outResponse := cCtx.String("out-response")
	attestationTypeStr := cCtx.String("attestation-type")
	expectedMeasurementsPath := cCtx.String("expected-measurements")
	overrideAzurev6Tcbinfo := cCtx.Bool("override-azurev6-tcbinfo")

	// Setup logging
	log := common.SetupLogger(&common.LoggingOpts{
		Debug:   logDebug,
		JSON:    false,
		Service: "attested-get",
		Version: common.Version,
	})

	// Sanity-check addr
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
		validators = append(validators, createAzureTDXValidator(log, overrideAzurev6Tcbinfo))
	case proxy.AttestationDCAPTDX:
		validators = append(validators, createDCAPTDXValidator(log))
	case proxy.AttestationAuto:
		// In auto mode, add all validators to support any attestation type
		log.Info("Auto mode: creating validators for all supported attestation types")
		validators = append(validators, createAzureTDXValidator(log, overrideAzurev6Tcbinfo))
		validators = append(validators, createDCAPTDXValidator(log))
	default:
		log.Error("unsupported attestation type, see --help for available options")
		return errors.New("unsupported attestation type")
	}

	// Load expected measurements from file or URL (if provided)
	var expectedMeasurements *multimeasurements.MultiMeasurements
	if expectedMeasurementsPath != "" {
		log.Info("Loading expected measurements from " + expectedMeasurementsPath + " ...")
		expectedMeasurements, err = multimeasurements.New(expectedMeasurementsPath)
		log.With("measurements", expectedMeasurements.Count()).Info("Measurements loaded")
		if err != nil {
			return err
		}
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
	atlsVariant, extractedMeasurements, err := proxy.GetMeasurementsFromTLS(resp.TLS.PeerCertificates, []asn1.ObjectIdentifier{variant.AzureTDX{}.OID(), variant.QEMUTDX{}.OID()})
	if err != nil {
		log.Error("Error in getMeasurementsFromTLS", "err", err)
		return err
	}

	printableMeasurements := make(map[uint32]string)
	for k, v := range extractedMeasurements {
		printableMeasurements[k] = fmt.Sprintf("%x", v)
	}

	marshaledPcrs, err := json.MarshalIndent(printableMeasurements, "", "    ")
	if err != nil {
		return errors.New("could not marshal measurement extracted from tls extension")
	}

	log.Info(fmt.Sprintf("Measurements for %s with %d entries:", atlsVariant.String(), len(extractedMeasurements)))
	fmt.Println(string(marshaledPcrs))
	if outMeasurements != "" {
		if err := os.WriteFile(outMeasurements, marshaledPcrs, 0o644); err != nil {
			return err
		}
	}

	// Compare against expected measurements
	if expectedMeasurements != nil {
		found, foundMeasurement := expectedMeasurements.Contains(extractedMeasurements)
		if found {
			log.With("matchedMeasurements", foundMeasurement.MeasurementID).Info("Measurements match expected measurements ✅")
		} else {
			log.Error("Measurements do not match expected measurements! ❌")
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
