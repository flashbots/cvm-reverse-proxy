package proxy

import (
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"os"

	"cvm-reverse-proxy/internal/atls"
	azure_tdx "cvm-reverse-proxy/internal/attestation/azure/tdx"
	"cvm-reverse-proxy/internal/attestation/measurements"
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

func CreateAttestationValidators(attestationType AttestationType, jsonMeasurementsPath string) ([]atls.Validator, error) {
	if attestationType == AttestationNone {
		return nil, nil
	}

	jsonMeasurements, err := os.ReadFile(jsonMeasurementsPath)
	if err != nil {
		return nil, err
	}

	var measurementsStruct measurements.M
	err = json.Unmarshal(jsonMeasurements, &measurementsStruct)
	if err != nil {
		return nil, err
	}

	switch attestationType {
	case AttestationAzureTDX:
		attConfig := config.DefaultForAzureTDX()
		attConfig.SetMeasurements(measurementsStruct)
		return []atls.Validator{azure_tdx.NewValidator(attConfig, AttestationLogger{})}, nil
	default:
		return nil, errors.New("invalid attestation-type passed in")
	}
}

type AttestationLogger struct{}

func (w AttestationLogger) Info(format string, args ...any) {
	log.Printf(format, args...)
}

func (w AttestationLogger) Warn(format string, args ...any) {
	log.Printf(format, args...)
}
