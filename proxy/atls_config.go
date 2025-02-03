// Package proxy contains the core proxy functionality and aTLS configuration
package proxy

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	azure_tdx "github.com/flashbots/cvm-reverse-proxy/internal/attestation/azure/tdx"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/measurements"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
	"github.com/flashbots/cvm-reverse-proxy/internal/cloud/cloudprovider"
	"github.com/flashbots/cvm-reverse-proxy/internal/config"
	"github.com/flashbots/cvm-reverse-proxy/multimeasurements"
	dcap_tdx "github.com/flashbots/cvm-reverse-proxy/tdx"
)

type AttestationType string

const (
	AttestationNone     AttestationType = "none"
	AttestationAuto     AttestationType = "auto"
	AttestationAzureTDX AttestationType = "azure-tdx"
	AttestationDCAPTDX  AttestationType = "dcap-tdx"
)

const AvailableAttestationTypes string = "none, auto, azure-tdx, dcap-tdx"

func ParseAttestationType(attestationType string) (AttestationType, error) {
	switch attestationType {
	case string(AttestationNone):
		return AttestationNone, nil
	case string(AttestationAuto):
		return AttestationAuto, nil
	case string(AttestationAzureTDX):
		return AttestationAzureTDX, nil
	case string(AttestationDCAPTDX):
		return AttestationDCAPTDX, nil
	default:
		return AttestationType(""), errors.New("invalid attestation-type passed in")
	}
}

func CreateAttestationIssuer(log *slog.Logger, attestationType AttestationType) (atls.Issuer, error) {
	switch attestationType {
	case AttestationNone:
		return nil, nil
	case AttestationAzureTDX:
		return azure_tdx.NewIssuer(log), nil
	case AttestationDCAPTDX:
		return dcap_tdx.NewIssuer(log), nil
	default:
		return nil, errors.New("invalid attestation-type passed in")
	}
}

// DetectAttestationType determines the attestation type based on environment
func DetectAttestationType() AttestationType {
	// Check for TDX device files - these indicate DCAP TDX
	_, tdxErr1 := os.Stat("/dev/tdx-guest")
	_, tdxErr2 := os.Stat("/dev/tdx_guest")
	if tdxErr1 == nil || tdxErr2 == nil {
		return AttestationDCAPTDX
	}

	// Try Azure TDX attestation - if it works, we're in Azure TDX
	issuer := azure_tdx.NewIssuer(nil) // nil logger for detection
	_, err := issuer.Issue(context.Background(), []byte("test"), []byte("test"))
	if err == nil {
		return AttestationAzureTDX
	}

	return AttestationNone
}

func CreateAttestationValidators(log *slog.Logger, attestationType AttestationType, jsonMeasurementsPath string) ([]atls.Validator, error) {
	if attestationType == AttestationAuto {
                attestationType = DetectAttestationType()
		log.With("detected_attestation", attestationType).Info("Auto-detected attestation type")
        }

	if attestationType == AttestationNone {
		return nil, nil
	}

	jsonMeasurements, err := os.ReadFile(jsonMeasurementsPath)
	if err != nil {
		return nil, err
	}

	var parsedMeasurements []multimeasurements.MeasurementsContainer
	err = json.Unmarshal(jsonMeasurements, &parsedMeasurements)
	if err != nil {
		return nil, err
	}

	switch attestationType {
	case AttestationAzureTDX:
		validators := []atls.Validator{}
		for _, measurement := range parsedMeasurements {
			attConfig := config.DefaultForAzureTDX()
			attConfig.SetMeasurements(measurement.Measurements)
			validators = append(validators, azure_tdx.NewValidator(attConfig, AttestationLogger{Log: log}))
		}
		return []atls.Validator{NewMultiValidator(validators)}, nil
	case AttestationDCAPTDX:
		validators := []atls.Validator{}
		for _, measurement := range parsedMeasurements {
			attConfig := &config.QEMUTDX{Measurements: measurements.DefaultsFor(cloudprovider.QEMU, variant.QEMUTDX{})}
			attConfig.SetMeasurements(measurement.Measurements)
			validators = append(validators, dcap_tdx.NewValidator(attConfig, AttestationLogger{Log: log}))
		}
		return []atls.Validator{NewMultiValidator(validators)}, nil
	default:
		return nil, errors.New("invalid attestation-type passed in")
	}
}

func ExtractMeasurementsFromExtension(ext *pkix.Extension, v variant.Variant) (map[uint32][]byte, error) {
	switch v {
	case variant.AzureTDX{}:
		measurements, err := azure_tdx.ParseAzureTDXAttestationMeasurements(ext.Value)
		if err != nil {
			return nil, errors.New("could not parse measurements from raw attestations document")
		}
		return measurements, nil
	case variant.QEMUTDX{}:
		measurements, err := dcap_tdx.ParseDcapTDXAttestationMeasurementsRaw(ext.Value)
		if err != nil {
			return nil, errors.New("could not parse measurements from raw attestations document")
		}
		return measurements, nil
	default:
		return nil, errors.New("unsupported ATLS variant")
	}
}

type AttestationLogger struct {
	Log *slog.Logger
}

func (w AttestationLogger) Info(format string, args ...any) {
	w.Log.Log(context.TODO(), slog.LevelInfo, fmt.Sprintf(format, args...))
}

func (w AttestationLogger) Debug(format string, args ...any) {
	w.Log.Log(context.TODO(), slog.LevelDebug, fmt.Sprintf(format, args...))
}

func (w AttestationLogger) Warn(format string, args ...any) {
	w.Log.Log(context.TODO(), slog.LevelWarn, fmt.Sprintf(format, args...))
}
