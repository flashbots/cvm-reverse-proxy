package main

//
// Make a HTTP GET request over a TEE-attested connection (to a server with aTLS support),
// and print the verified measurements and the response payload.
//
// Currently only works for Azure TDX but should be easy to expand.
//
// Usage:
//
//   go run cmd/get-measurements/main.go --addr=https://instance_ip:port
//
// Can also save the verified measurements and the response body to files:
//
//   go run cmd/get-measurements/main.go --addr=https://instance_ip:port --out-measurements=measurements.json --out-response=response.txt
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
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
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
	&cli.BoolFlag{
		Name:  "log-debug",
		Value: false,
		Usage: "log debug messages",
	},
}

func main() {
	app := &cli.App{
		Name:   "get-measurements",
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

	// Setup logging
	log := common.SetupLogger(&common.LoggingOpts{
		Debug:   logDebug,
		JSON:    false,
		Service: "get-measurements",
		Version: common.Version,
	})

	if !strings.HasPrefix(addr, "https://") {
		return errors.New("address needs to start with https://")
	}

	log.Info("Getting verified measurements from " + addr + " ...")
	// Prepare aTLS stuff
	serverAttestationType := proxy.AttestationAzureTDX
	issuer, err := proxy.CreateAttestationIssuer(log, serverAttestationType)
	if err != nil {
		log.Error("could not create attestation issuer", "err", err)
		return err
	}

	validators, err := proxy.CreateAttestationValidators(log, serverAttestationType, "measurements-empty.json")
	if err != nil {
		log.Error("could not create attestation validators", "err", err)
		return err
	}

	tlsConfig, err := atls.CreateAttestationClientTLSConfig(issuer, validators)
	if err != nil {
		log.Error("could not create atls config", "err", err)
		return err
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(addr)
	if err != nil {
		return err
	}
	certs := resp.TLS.PeerCertificates

	// Extract the aTLS variant and measurements from the TLS connection
	// certs := conn.ConnectionState().PeerCertificates
	atlsVariant, extractedMeasurements, err := proxy.GetMeasurementsFromTLS(certs, []asn1.ObjectIdentifier{variant.AzureTDX{}.OID()})
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

	log.Info("Variant: " + atlsVariant.String())
	log.Info(fmt.Sprintf("Measurements for %s with %d entries:", atlsVariant.String(), len(measurementsInHeaderFormat)))
	fmt.Println(string(marshaledPcrs))
	if outMeasurements != "" {
		if err := os.WriteFile(outMeasurements, marshaledPcrs, 0644); err != nil {
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
		if err := os.WriteFile(outResponse, msg, 0644); err != nil {
			return err
		}
	}

	return nil
}
