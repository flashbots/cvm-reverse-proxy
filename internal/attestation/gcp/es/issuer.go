/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package es

import (
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/gcp"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/vtpm"

	tpmclient "github.com/google/go-tpm-tools/client"
)

// Issuer for GCP confidential VM attestation.
type Issuer struct {
	variant.GCPSEVES
	*vtpm.Issuer
}

// NewIssuer initializes a new GCP Issuer.
func NewIssuer(log attestation.Logger) *Issuer {
	return &Issuer{
		Issuer: vtpm.NewIssuer(
			vtpm.OpenVTPM,
			tpmclient.GceAttestationKeyRSA,
			gcp.GCEInstanceInfo(gcp.MetadataClient{}),
			log,
		),
	}
}
