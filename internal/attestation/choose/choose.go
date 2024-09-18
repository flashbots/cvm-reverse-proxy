/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package choose

import (
	"fmt"

	"cvm-reverse-proxy/internal/atls"
	"cvm-reverse-proxy/internal/attestation"
	"cvm-reverse-proxy/internal/attestation/aws/nitrotpm"
	awssnp "cvm-reverse-proxy/internal/attestation/aws/snp"
	azuresnp "cvm-reverse-proxy/internal/attestation/azure/snp"
	azuretdx "cvm-reverse-proxy/internal/attestation/azure/tdx"
	"cvm-reverse-proxy/internal/attestation/azure/trustedlaunch"
	"cvm-reverse-proxy/internal/attestation/gcp/es"
	gcpsnp "cvm-reverse-proxy/internal/attestation/gcp/snp"
	"cvm-reverse-proxy/internal/attestation/qemu"
	"cvm-reverse-proxy/internal/attestation/tdx"
	"cvm-reverse-proxy/internal/attestation/variant"
	"cvm-reverse-proxy/internal/config"
)

// Issuer returns the issuer for the given variant.
func Issuer(attestationVariant variant.Variant, log attestation.Logger) (atls.Issuer, error) {
	switch attestationVariant {
	case variant.AWSSEVSNP{}:
		return awssnp.NewIssuer(log), nil
	case variant.AWSNitroTPM{}:
		return nitrotpm.NewIssuer(log), nil
	case variant.AzureTrustedLaunch{}:
		return trustedlaunch.NewIssuer(log), nil
	case variant.AzureSEVSNP{}:
		return azuresnp.NewIssuer(log), nil
	case variant.AzureTDX{}:
		return azuretdx.NewIssuer(log), nil
	case variant.GCPSEVES{}:
		return es.NewIssuer(log), nil
	case variant.GCPSEVSNP{}:
		return gcpsnp.NewIssuer(log), nil
	case variant.QEMUVTPM{}:
		return qemu.NewIssuer(log), nil
	case variant.QEMUTDX{}:
		return tdx.NewIssuer(log), nil
	case variant.Dummy{}:
		return atls.NewFakeIssuer(variant.Dummy{}), nil
	default:
		return nil, fmt.Errorf("unknown attestation variant: %s", attestationVariant)
	}
}

// Validator returns the validator for the given variant.
func Validator(cfg config.AttestationCfg, log attestation.Logger) (atls.Validator, error) {
	switch cfg := cfg.(type) {
	case *config.AWSSEVSNP:
		return awssnp.NewValidator(cfg, log), nil
	case *config.AWSNitroTPM:
		return nitrotpm.NewValidator(cfg, log), nil
	case *config.AzureTrustedLaunch:
		return trustedlaunch.NewValidator(cfg, log), nil
	case *config.AzureSEVSNP:
		return azuresnp.NewValidator(cfg, log), nil
	case *config.AzureTDX:
		return azuretdx.NewValidator(cfg, log), nil
	case *config.GCPSEVES:
		return es.NewValidator(cfg, log)
	case *config.GCPSEVSNP:
		return gcpsnp.NewValidator(cfg, log)
	case *config.QEMUVTPM:
		return qemu.NewValidator(cfg, log), nil
	case *config.QEMUTDX:
		return tdx.NewValidator(cfg, log), nil
	case *config.DummyCfg:
		return atls.NewFakeValidator(variant.Dummy{}), nil
	default:
		return nil, fmt.Errorf("unknown attestation variant: %s", cfg.GetVariant())
	}
}
