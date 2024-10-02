package proxy

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"cvm-reverse-proxy/internal/atls"
	azure_tdx "cvm-reverse-proxy/internal/attestation/azure/tdx"
	"cvm-reverse-proxy/internal/attestation/measurements"
	"cvm-reverse-proxy/internal/attestation/variant"
	"cvm-reverse-proxy/internal/config"
)

type AttestationType string

const (
	AttestationNone     AttestationType = "none"
	AttestationAzureTDX AttestationType = "azure-tdx"
)

const AvailableAttestationTypes string = "none, azure-tdx"

func ParseAttestationType(attestationType string) (AttestationType, error) {
	switch attestationType {
	case string(AttestationNone):
		return AttestationNone, nil
	case string(AttestationAzureTDX):
		return AttestationAzureTDX, nil
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
	default:
		return nil, errors.New("invalid attestation-type passed in")
	}
}

func CreateAttestationValidators(log *slog.Logger, attestationType AttestationType, jsonMeasurementsPath string) ([]atls.Validator, error) {
	if attestationType == AttestationNone {
		return nil, nil
	}

	jsonMeasurements, err := os.ReadFile(jsonMeasurementsPath)
	if err != nil {
		return nil, err
	}

	parsedMeasurements := make(map[string]measurements.M)
	err = json.Unmarshal(jsonMeasurements, &parsedMeasurements)
	if err != nil {
		return nil, err
	}

	switch attestationType {
	case AttestationAzureTDX:
		validators := []atls.Validator{}
		for _, measurement := range parsedMeasurements {
			attConfig := config.DefaultForAzureTDX()
			attConfig.SetMeasurements(measurement)
			validators = append(validators, azure_tdx.NewValidator(attConfig, AttestationLogger{Log: log}))
		}
		return []atls.Validator{NewMultiValidator(validators)}, nil
	default:
		return nil, errors.New("invalid attestation-type passed in")
	}
}

func ExtractExtensionATLSVariant(ext *pkix.Extension) (variant.Variant, error) {
	return variant.FromString(ext.Id.String())
}

func ExtractMeasurementsFromExtension(ext *pkix.Extension, v variant.Variant) (map[uint32][]byte, error) {
	switch v {
	case variant.AzureTDX{}:
		// TODO: make sure that all extensions had their quotes validated at this point!
		measurements, err := azure_tdx.ParseAzureTDXAttestationMeasurements(ext.Value)
		if err != nil {
			return nil, errors.New("could not parse measurements from raw attestations document")
		}
		return measurements, nil
	default:
		return nil, errors.New("unsupported ATLS variant!")
	}
}

type AttestationLogger struct {
	Log *slog.Logger
}

func (w AttestationLogger) Info(format string, args ...any) {
	w.Log.Log(context.TODO(), slog.LevelInfo, fmt.Sprintf(format, args...))
}

func (w AttestationLogger) Warn(format string, args ...any) {
	w.Log.Log(context.TODO(), slog.LevelWarn, fmt.Sprintf(format, args...))
}
