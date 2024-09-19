package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"

	"cvm-reverse-proxy/internal/atls"
	azure_tdx "cvm-reverse-proxy/internal/attestation/azure/tdx"
	"cvm-reverse-proxy/internal/attestation/measurements"
	dcap_tdx "cvm-reverse-proxy/internal/attestation/tdx"
	"cvm-reverse-proxy/internal/config"
	cvm_tdx "cvm-reverse-proxy/tdx"
)

type AttestationType string

const (
	AttestationNone     AttestationType = "none"
	AttestationAzureTDX AttestationType = "azure-tdx"
	AttestationDCAPTDX  AttestationType = "dcap-tdx"
)

func ParseAttestationType(attestationType string) (AttestationType, error) {
	switch attestationType {
	case string(AttestationNone):
		return AttestationNone, nil
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
		return cvm_tdx.NewIssuer(log), nil
	default:
		return nil, errors.New("invalid attestation-type passed in")
	}
}

func CreateAttestationValidators(attestationType AttestationType, jsonMeasurementsPath string) ([]atls.Validator, error) {
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
	case AttestationNone:
		return nil, nil
	case AttestationAzureTDX:
		attConfig := config.DefaultForAzureTDX()
		attConfig.SetMeasurements(measurementsStruct)
		return []atls.Validator{azure_tdx.NewValidator(attConfig, AttestationLogger{})}, nil
	case AttestationDCAPTDX:
		attConfig := config.QEMUTDX{Measurements: measurementsStruct}
		return []atls.Validator{dcap_tdx.NewValidator(&attConfig, AttestationLogger{})}, nil
	default:
		return nil, errors.New("invalid attestation-type passed in")
	}
}

type AttestationLogger struct{}

func (w AttestationLogger) Info(format string, args ...any) {
	log.Print(fmt.Sprintf(format, args...))
}

func (w AttestationLogger) Warn(format string, args ...any) {
	log.Print(fmt.Sprintf(format, args...))
}
