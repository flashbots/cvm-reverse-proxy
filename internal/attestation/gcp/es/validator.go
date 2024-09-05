/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package es

import (
	"fmt"

	"cvm-reverse-proxy/internal/attestation"
	"cvm-reverse-proxy/internal/attestation/gcp"
	"cvm-reverse-proxy/internal/attestation/variant"
	"cvm-reverse-proxy/internal/attestation/vtpm"
	"cvm-reverse-proxy/internal/config"

	"github.com/google/go-tpm-tools/proto/attest"
)

const minimumGceVersion = 1

// Validator for GCP confidential VM attestation.
type Validator struct {
	variant.GCPSEVES
	*vtpm.Validator
}

// NewValidator initializes a new GCP validator with the provided PCR values specified in the config.
func NewValidator(cfg *config.GCPSEVES, log attestation.Logger) (*Validator, error) {
	getTrustedKey, err := gcp.TrustedKeyGetter(variant.GCPSEVES{}, gcp.NewRESTClient)
	if err != nil {
		return nil, fmt.Errorf("create trusted key getter: %v", err)
	}

	return &Validator{
		Validator: vtpm.NewValidator(
			cfg.Measurements,
			getTrustedKey,
			validateCVM,
			log,
		),
	}, nil
}

// validateCVM checks that the machine state represents a GCE AMD-SEV VM.
func validateCVM(_ vtpm.AttestationDocument, state *attest.MachineState) error {
	gceVersion := state.Platform.GetGceVersion()
	if gceVersion < minimumGceVersion {
		return fmt.Errorf("outdated GCE version: %v (require >= %v)", gceVersion, minimumGceVersion)
	}

	tech := state.Platform.Technology
	wantTech := attest.GCEConfidentialTechnology_AMD_SEV
	if tech != wantTech {
		return fmt.Errorf("unexpected confidential technology: %v (expected: %v)", tech, wantTech)
	}

	return nil
}
