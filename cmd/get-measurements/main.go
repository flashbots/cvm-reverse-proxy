package main

//
// CLI tool to get and print verified measurements from an aTLS server.
//
// Currently only works for Azure TDX but should be easy to expand.
//
// Usage:
//
//	 go run cmd/get-measurements/main.go instance_ip:port
//

import (
	"crypto/tls"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/flashbots/cvm-reverse-proxy/common"
	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
	"github.com/flashbots/cvm-reverse-proxy/proxy"
	"github.com/urfave/cli/v2" // imports as package "cli"
)

var flags []cli.Flag = []cli.Flag{
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

func runClient(cCtx *cli.Context) error {
	logDebug := cCtx.Bool("log-debug")

	// Setup logging
	log := common.SetupLogger(&common.LoggingOpts{
		Debug:   logDebug,
		JSON:    false,
		Service: "get-measurements",
		Version: common.Version,
	})

	addr := cCtx.Args().Get(0)
	if addr == "" {
		log.Error("Please provide an address as cli argument")
		return errors.New("provide an address as argument")
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

	// Open connection to the TDX server and verify the aTLS attestation
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		log.Error("Error in Dial", "err", err)
		return err
	}
	defer conn.Close()

	// Extract the aTLS variant and measurements from the TLS connection
	certs := conn.ConnectionState().PeerCertificates
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
	// log.Info("Measurements", "measurements", string(marshaledPcrs))
	fmt.Println(string(marshaledPcrs))

	return nil
}
