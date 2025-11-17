/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package tdx

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/flashbots/cvm-reverse-proxy/internal/attestation"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/azure"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/vtpm"
	"github.com/flashbots/cvm-reverse-proxy/internal/config"
	certutil "github.com/flashbots/cvm-reverse-proxy/internal/crypto"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
)

const AZURE_V6_BAD_FMSPC = "90c06f000000"

// ameRoot is the AME root CA certificate used to sign Azure's AME Infra CA certificates.
// The certificate can be found at http://crl.microsoft.com/pkiinfra/certs/AMERoot_ameroot.crt.
// This is the same root CA used by both TrustedLaunch and TDX VMs.
var ameRoot = mustParseX509("-----BEGIN CERTIFICATE-----\nMIIFVjCCAz6gAwIBAgIQJdrLVcnGd4FAnlaUgt5N/jANBgkqhkiG9w0BAQsFADA8\nMRMwEQYKCZImiZPyLGQBGRYDR0JMMRMwEQYKCZImiZPyLGQBGRYDQU1FMRAwDgYD\nVQQDEwdhbWVyb290MB4XDTE2MDUyNDIyNTI1NFoXDTI2MDUyNDIyNTcwM1owPDET\nMBEGCgmSJomT8ixkARkWA0dCTDETMBEGCgmSJomT8ixkARkWA0FNRTEQMA4GA1UE\nAxMHYW1lcm9vdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALv4uChY\noVuO+bxBOcn8v4FajoGkxo0YgVwEqEPDVPI6vzmnEqHVhQ1GMVeDyiRrgQT1vCk1\nHMMzo9LlWowPrzbXOwjOTFbXc36+UU41yNN2GeNa49RXbAkfbzKE/SYLfbqOD0dN\nZLwvOhgIb25oA1eAxW/DI/hvJLLKh2SscvkIyd3o2BUeFm7NtyYG/buCKJh8lOq8\n0iBwRoEoInb0vhorHaswSMmqY1g+AJndY/M7uGUqkhDGBhLu53bU9wbUPHsEI+wa\nq6WypCijZYT+C4BS5GJrEPZ2O92pztd+ULqhzNRoPj5RuElUww7+z5RnbCaupyBY\nOmmJMH30EiRSq8dK/irixXXwJraSywR5kyfmAkv6GYWlRlxFUiK3/co47JLA3TDK\nN0wfutbpqxdZQYyGfO2nZrr5JbKfSU0sMtOZDkK6hlafV++hfkVSvFfNHE5B5uN1\nMK6agl1dzi28HfJT9aO7cmjGxl1SJ5qoCvcwZNQ2SPHFdrslcwXEFOMDaEzVOA3V\n7j3+6lrT8sHXg0sErkcd8lrBImfzhLxM/Wh8CgOUNeUu3flUoxmFv3el+QWalSNy\n2SXs2NgWuYE5Iog7CHD/xCnoEnZwwjqLkrro4hYWE4Xj3VlA2Eq+VxqJOgdyFl3m\nckSZ08OcwLeprY4+2GEvCXNGNdXUmNNgk2PvAgMBAAGjVDBSMAsGA1UdDwQEAwIB\nhjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBQpXlFeZK40ueusnA2njHUB\n0QkLKDAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQsFAAOCAgEAcznFDnJx\nsXaazFY1DuIPvUaiWS7ELxAVXMGZ7ROjLrDq1FNYVewL4emDqyEIEMFncec8rqyk\nVBvLQA5YqMCxQWJpL0SlgRSknzLh9ZVcQw1TshC49/XV2N/CLOuyInEQwS//46so\nT20Cf8UGUiOK472LZlvM4KchyDR3FTNtmMg0B/LKVjevpX9sk5MiyjjLUj3jtPIP\n7jpsfZDd/BNsg/89kpsIF5O64I7iYFj3MHu9o4UJcEX0hRt7OzUxqa9THTssvzE5\nVkWo8Rtou2T5TobKV6Rr5Ob9wchLXqVtCyZF16voEKheBnalhGUvErI/6VtBwLb7\n13C0JkKLBNMen+HClNliicVIaubnpY2g+AqxOgKBHiZnzq2HhE1qqEUf4VfqahNU\niaXtbtyo54f2dCf9UL9uG9dllN3nxBE/Y/aWF6E1M8Bslj1aYAtfUQ/xlhEXCly6\nzohw697i3XFUt76RwvfW8quvqdH9Mx0PBpYo4wJJRwAecSJQNy6wIJhAuDgOemXJ\nYViBi/bDnhPcFEVQxsypQSw91BUw7Mxh+W59H5MC25SAIw9fLMT9LRqSYpPyasNp\n4nACjR+bv/6cI+ICOrGmD2mrk2c4dNnYpDx96FfX/Y158RV0wotqIglACk6m1qyo\nyTra6P0Kvo6xz4KaVm8F7VDzUP+heAAhPAs=\n-----END CERTIFICATE-----\n")

// Validator for Azure confidential VM attestation using TDX.
type Validator struct {
	variant.AzureTDX
	*vtpm.Validator
	cfg *config.AzureTDX

	getter       trust.HTTPSGetter
	hclValidator hclAkValidator

	tcbOverride func(pcs.TcbInfo) pcs.TcbInfo
	log         attestation.Logger
}

// NewValidator returns a new Validator for Azure confidential VM attestation using TDX.
func NewValidator(cfg *config.AzureTDX, log attestation.Logger) *Validator {
	v := &Validator{
		cfg:          cfg,
		getter:       trust.DefaultHTTPSGetter(),
		hclValidator: &azure.HCLAkValidator{},
		log:          log,
	}

	v.Validator = vtpm.NewValidator(
		cfg.Measurements,
		v.getTrustedTPMKey,
		func(vtpm.AttestationDocument, *attest.MachineState) error {
			return nil
		},
		log,
	)

	return v
}

func (v *Validator) SetTcbOverride(overrideFn func(pcs.TcbInfo) pcs.TcbInfo) *Validator {
	v.tcbOverride = overrideFn
	return v
}

func (v *Validator) getTrustedTPMKey(_ context.Context, attDoc vtpm.AttestationDocument, _ []byte) (crypto.PublicKey, error) {
	var instanceInfo InstanceInfo
	if err := json.Unmarshal(attDoc.InstanceInfo, &instanceInfo); err != nil {
		return nil, err
	}

	quotePb, err := abi.QuoteToProto(instanceInfo.AttestationReport)
	if err != nil {
		return nil, err
	}
	quote, ok := quotePb.(*tdx.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("unexpected quote type: %T", quote)
	}

	if err := v.validateQuote(quote); err != nil {
		return nil, err
	}

	// Decode the public area of the attestation key and validate its trustworthiness.
	pubArea, err := tpm2.DecodePublic(attDoc.Attestation.AkPub)
	if err != nil {
		return nil, err
	}
	if err = v.hclValidator.Validate(instanceInfo.RuntimeData, quote.TdQuoteBody.ReportData, pubArea.RSAParameters); err != nil {
		return nil, fmt.Errorf("validating HCLAkPub: %w", err)
	}

	// Verify the vTPM AK certificate chain to prevent forging attestation attacks
	// This ensures the attestation key is actually signed by Azure's CA
	if err := v.verifyAKCertificate(instanceInfo, &pubArea); err != nil {
		return nil, fmt.Errorf("verifying AK certificate: %w", err)
	}

	return pubArea.Key()
}

func (v *Validator) validateQuote(tdxQuote *tdx.QuoteV4) error {
	roots := x509.NewCertPool()
	roots.AddCert((*x509.Certificate)(&v.cfg.IntelRootKey))

	if err := verify.TdxQuote(tdxQuote, &verify.Options{
		CheckRevocations: true,
		GetCollateral:    true,
		PatchTCBInfo:     v.tcbOverride,
		TrustedRoots:     roots,
		Getter:           v.getter,
	}); err != nil {
		return err
	}

	// Hacky way to log every time we validate the outdated v6 tcb
	if v.tcbOverride != nil {
		if chain, err := verify.ExtractChainFromQuote(tdxQuote); err == nil {
			if exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate); err == nil {
				if exts.FMSPC == AZURE_V6_BAD_FMSPC {
					if tdxQuote.TdQuoteBody.TeeTcbSvn[7] == 3 {
						v.log.Warn("allowing azure's outdated SEAM loader")
					}
				}
			}
		}
	}

	if err := validate.TdxQuote(tdxQuote, &validate.Options{
		HeaderOptions: validate.HeaderOptions{
			MinimumQeSvn:  v.cfg.QESVN.Value,
			MinimumPceSvn: v.cfg.PCESVN.Value,
			QeVendorID:    v.cfg.QEVendorID.Value,
		},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			MinimumTeeTcbSvn: v.cfg.TEETCBSVN.Value,
			MrSeam:           v.cfg.MRSeam,
			Xfam:             v.cfg.XFAM.Value,
		},
	}); err != nil {
		return err
	}

	return nil
}

// verifyAKCertificate verifies the vTPM attestation key certificate chain.
// This prevents attacks where an attacker could forge attestation by using their own key.
func (v *Validator) verifyAKCertificate(instanceInfo InstanceInfo, pubArea *tpm2.Public) error {
	v.log.Info("Starting vTPM AK certificate verification")

	// Parse the AK certificate
	akCert, err := x509.ParseCertificate(instanceInfo.AkCert)
	if err != nil {
		return fmt.Errorf("parsing attestation key certificate: %w", err)
	}
	v.log.Info(fmt.Sprintf("AK Certificate Subject: %s", akCert.Subject.String()))
	v.log.Info(fmt.Sprintf("AK Certificate Issuer: %s", akCert.Issuer.String()))

	// Setup certificate pools for verification
	roots := x509.NewCertPool()
	roots.AddCert(ameRoot)
	v.log.Info(fmt.Sprintf("AME Root Certificate Subject: %s", ameRoot.Subject.String()))

	intermediates := x509.NewCertPool()

	// Parse the CA certificate if provided
	// For TDX, the AK certificate may be issued directly by the root CA
	if len(instanceInfo.CA) > 0 {
		akCertCA, err := x509.ParseCertificate(instanceInfo.CA)
		if err != nil {
			v.log.Warn(fmt.Sprintf("Failed to parse CA certificate: %v - will try direct root verification", err))
		} else {
			v.log.Info(fmt.Sprintf("CA Certificate Subject: %s", akCertCA.Subject.String()))
			v.log.Info(fmt.Sprintf("CA Certificate Issuer: %s", akCertCA.Issuer.String()))
			intermediates.AddCert(akCertCA)
		}
	} else {
		v.log.Info("No CA certificate provided - verifying directly against root CA")
	}

	// Verify the certificate chain
	v.log.Info("Verifying certificate chain against AME root CA")
	if _, err := akCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		v.log.Warn(fmt.Sprintf("Certificate chain verification failed: %v", err))
		return fmt.Errorf("verifying attestation key certificate chain: %w", err)
	}
	v.log.Info("Certificate chain verification successful")

	// Verify that the public key in the certificate matches the TPM's AK public key
	pubKey, err := pubArea.Key()
	if err != nil {
		return fmt.Errorf("getting public key from TPM: %w", err)
	}

	pubKeyRSA, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("attestation key is not an RSA key")
	}

	if !pubKeyRSA.Equal(akCert.PublicKey) {
		v.log.Warn("Certificate public key does not match TPM attestation key")
		return errors.New("certificate public key does not match attestation key")
	}
	v.log.Info("Certificate public key matches TPM attestation key")
	v.log.Info("vTPM AK certificate verification completed successfully")

	return nil
}

func mustParseX509(pem string) *x509.Certificate {
	cert, err := certutil.PemToX509Cert([]byte(pem))
	if err != nil {
		panic(err)
	}
	return cert
}

type hclAkValidator interface {
	Validate(runtimeDataRaw []byte, reportData []byte, rsaParameters *tpm2.RSAParams) error
}

var ParseAzureTDXAttestationMeasurements = vtpm.ParseAzureTDXAttestationMeasurements
