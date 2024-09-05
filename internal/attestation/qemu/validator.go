/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package qemu

import (
	"context"
	"crypto"

	"cvm-reverse-proxy/internal/attestation"
	"cvm-reverse-proxy/internal/attestation/variant"
	"cvm-reverse-proxy/internal/attestation/vtpm"
	"cvm-reverse-proxy/internal/config"

	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
)

// Validator for QEMU VM attestation.
type Validator struct {
	variant.QEMUVTPM
	*vtpm.Validator
}

// NewValidator initializes a new QEMU validator with the provided PCR values.
func NewValidator(cfg *config.QEMUVTPM, log attestation.Logger) *Validator {
	return &Validator{
		Validator: vtpm.NewValidator(
			cfg.Measurements,
			unconditionalTrust,
			func(vtpm.AttestationDocument, *attest.MachineState) error { return nil },
			log,
		),
	}
}

// unconditionalTrust returns the given public key as the trusted attestation key.
func unconditionalTrust(_ context.Context, attDoc vtpm.AttestationDocument, _ []byte) (crypto.PublicKey, error) {
	pubArea, err := tpm2.DecodePublic(attDoc.Attestation.AkPub)
	if err != nil {
		return nil, err
	}
	return pubArea.Key()
}
