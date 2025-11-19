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

// microsoftRSADevicesRoot2021 is the root CA certificate used to sign Azure TDX vTPM certificates.
// This is different from the AME root CA used by TrustedLaunch VMs.
// The certificate can be downloaded from:
// http://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Devices%20Root%20CA%202021.crt
var microsoftRSADevicesRoot2021 = mustParseX509(`-----BEGIN CERTIFICATE-----
MIIFkjCCA3qgAwIBAgIQGWCAkS2F96VGa+6hm2M3rjANBgkqhkiG9w0BAQwFADBa
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSsw
KQYDVQQDEyJNaWNyb3NvZnQgUlNBIERldmljZXMgUm9vdCBDQSAyMDIxMB4XDTIx
MDgyNjIzMzkxOFoXDTQ2MDgyNjIzNDcxNFowWjELMAkGA1UEBhMCVVMxHjAcBgNV
BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiTWljcm9zb2Z0IFJT
QSBEZXZpY2VzIFJvb3QgQ0EgMjAyMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBALF4kgr3bAptorWmkrM6u47osmLfg67KxZPE4W74Zw5Bu64tjEuzegcB
6lFkoXi2V4eLdIRshk3l14jul6ghCML/6gh4hYiTExky3XMY05wg0d1o+AdhuyvC
anXvQZratosnL+KhR2qFeagthciIrCibIIKX91LvqRl/Eg8uo82fl30gieB40Sun
Pe/SfMJLb7AYbQ95yHK8G1lTFUHkIfPbAY6SfkOBUpNJ6UAtjlAmIaHYpdcdOayf
qXyhW3+Hf0Ou2wiKYJihCqh3TaI2hqmiv4p4CScug9sDcTyafA6OYLyTe3vx7Krn
BOUvkSkTj80GrXSKCWnrw+bE7z0deptPuLS6+n83ImLsBZ3XYhX4iUPmTRSU9vr7
q0cZA8P8zAzLaeN+uK14l92u/7TMhkp5etmLE9DMd9MtnsLZSy18UpW4ZlBXxt9Z
w/RFKStlNbK5ILsI2HdSjgkF0DxZtNnCiEQehMu5DBfCdXo1P90iJhfF1MD+2Kh5
xeuDQEC7Dh3gUSXIkOm/72u1fE52r0uY+aH1TCQGbCrijI9Jf78lFbI7L6Ll3YAa
89MrDs2tAQG0SaJdabh4k5orqaJOgaqrrq61RzcMjlZGI3dOdL+f6romKOccFkm0
k+gwjvZ9xaJ5i9SB6Lq/GrA8YxzjmKHHVPmGGdm/v93R0oNGfyvxAgMBAAGjVDBS
MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSERIYG
AJg/LKqzxYnzrC7J5p0JAzAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwF
AAOCAgEAd3RAo42nyNbVvj+mxZ03VV+ceU6nCdgIS8RZfZBxf+lqupRzKUV9UW59
IRCSeMH3gHfGSVhmwH1AJHkFIhd5meSShF4lPPmvYMmrbfOrwiUunqz2aix/QkRp
geMOe10wm6dEHHAw/eNi3PWhc+jdGJNV0SdnqcwJg/t5db8Y7RCVW+tG3DtEa63U
B4sGNlBbaUffdSdYL5TCRXm2mkcCWruu/gmDTgoabFmI4j9ss0shsIxwqVVEq2zk
EH1ypZrHSmVrTRh9hPHWpkOxnh9yqpGDXcSll09ZZUBUhx7YUX6p+BTVWnuuyR4T
bXS8P6fUS5Q2WF0WR07BrGYlBqomsEwMhth1SmBKn6tXfQyWkgr4pVl5XkkC7Bfv
pmw90csy8ycwog+x4L9kO1Nr6OPwnJ9V39oMifNDxnvYVBX7EhjoiARPp+97feNJ
YwMt4Os/WSeD++IhBB9xVsrI+jZufySQ02C/w1LBFR6zPy+a+v+6WlvMxDBEDWOj
JyDQ6kzkWxIG35klzLnwHybuIsFIIR1QGL1l47eW2dM4hB9oCay6z3FX5xYBIFvA
yp8up+KbjfH/NIWfPBXhYMW64DagB9P2cW5LBRz+AzDA+JF/OdYpb6vxv3lzjLQb
U9zMFwSrzEF5o2Aa/n+xZ90Naj78AYaTM18DalA17037fjucDN8=
-----END CERTIFICATE-----`)

// azureVirtualTPMRoot2023 is the root CA for Azure vTPM (used by both Trusted Launch and TDX)
// Source: https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq
// Valid until: 2048-06-01
var azureVirtualTPMRoot2023 = mustParseX509(`-----BEGIN CERTIFICATE-----
MIIFsDCCA5igAwIBAgIQUfQx2iySCIpOKeDZKd5KpzANBgkqhkiG9w0BAQwFADBp
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTow
OAYDVQQDEzFBenVyZSBWaXJ0dWFsIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhv
cml0eSAyMDIzMB4XDTIzMDYwMTE4MDg1M1oXDTQ4MDYwMTE4MTU0MVowaTELMAkG
A1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE6MDgGA1UE
AxMxQXp1cmUgVmlydHVhbCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
MjAyMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALoMMwvdRJ7+bW00
adKE1VemNqJS+268Ure8QcfZXVOsVO22+PL9WRoPnWo0r5dVoomYGbobh4HC72s9
sGY6BGRe+Ui2LMwuWnirBtOjaJ34r1ZieNMcVNJT/dXW5HN/HLlm/gSKlWzqCEx6
gFFAQTvyYl/5jYI4Oe05zJ7ojgjK/6ZHXpFysXnyUITJ9qgjn546IJh/G5OMC3mD
fFU7A/GAi+LYaOHSzXj69Lk1vCftNq9DcQHtB7otO0VxFkRLaULcfu/AYHM7FC/S
q6cJb9Au8K/IUhw/5lJSXZawLJwHpcEYzETm2blad0VHsACaLNucZL5wBi8GEusQ
9Wo8W1p1rUCMp89pufxa3Ar9sYZvWeJlvKggWcQVUlhvvIZEnT+fteEvwTdoajl5
qSvZbDPGCPjb91rSznoiLq8XqgQBBFjnEiTL+ViaZmyZPYUsBvBY3lKXB1l2hgga
hfBIag4j0wcgqlL82SL7pAdGjq0Fou6SKgHnkkrV5CNxUBBVMNCwUoj5mvEjd5mF
7XPgfM98qNABb2Aqtfl+VuCkU/G1XvFoTqS9AkwbLTGFMS9+jCEU2rw6wnKuGv1T
x9iuSdNvsXt8stx4fkVeJvnFpJeAIwBZVgKRSTa3w3099k0mW8qGiMnwCI5SfdZ2
SJyD4uEmszsnieE6wAWd1tLLg1jvAgMBAAGjVDBSMA4GA1UdDwEB/wQEAwIBhjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRL/iZalMH2M8ODSCbd8+WwZLKqlTAQ
BgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEALgNAyg8I0ANNO/8I
2BhpTOsbywN2YSmShAmig5h4sCtaJSM1dRXwA+keY6PCXQEt/PRAQAiHNcOF5zbu
OU1Bw/Z5Z7k9okt04eu8CsS2Bpc+POg9js6lBtmigM5LWJCH1goMD0kJYpzkaCzx
1TdD3yjo0xSxgGhabk5Iu1soD3OxhUyIFcxaluhwkiVINt3Jhy7G7VJTlEwkk21A
oOrQxUsJH0f2GXjYShS1r9qLPzLf7ykcOm62jHGmLZVZujBzLIdNk1bljP9VuGW+
cISBwzkNeEMMFufcL2xh6s/oiUnXicFWvG7E6ioPnayYXrHy3Rh68XLnhfpzeCzv
bz/I4yMV38qGo/cAY2OJpXUuuD/ZbI5rT+lRBEkDW1kxHP8cpwkRwGopV8+gX2KS
UucIIN4l8/rrNDEX8T0b5U+BUqiO7Z5YnxCya/H0ZIwmQnTlLRTU2fW+OGG+xyIr
jMi/0l6/yWPUkIAkNtvS/yO7USRVLPbtGVk3Qre6HcqacCXzEjINcJhGEVg83Y8n
M+Y+a9J0lUnHytMSFZE85h88OseRS2QwqjozUo2j1DowmhSSUv9Na5Ae22ycciBk
EZSq8a4rSlwqthaELNpeoTLUk6iVoUkK/iLvaMvrkdj9yJY1O/gvlfN2aiNTST/2
bd+PA4RBToG9rXn6vNkUWdbLibU=
-----END CERTIFICATE-----`)

// globalVirtualTPMCA03 is the intermediate CA that issues TDX vTPM AK certificates
// Source: https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq
// Issuer: Azure Virtual TPM Root Certificate Authority 2023
// Valid: 2025-04-24 to 2027-04-24
var globalVirtualTPMCA03 = mustParseX509(`-----BEGIN CERTIFICATE-----
MIIFnDCCA4SgAwIBAgITMwAAAAknQOWscnsOpgAAAAAACTANBgkqhkiG9w0BAQwF
ADBpMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
MTowOAYDVQQDEzFBenVyZSBWaXJ0dWFsIFRQTSBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAyMDIzMB4XDTI1MDQyNDE4MDExN1oXDTI3MDQyNDE4MDExN1owJTEj
MCEGA1UEAxMaR2xvYmFsIFZpcnR1YWwgVFBNIENBIC0gMDMwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDYGYtis5ka0cxQkhU11jslgX6wzjR/UXQIFdUn
8juTUMJl91VokwUPX3WfXeog7mtbWyYWD8SI0BSnchRGlV8u3AhcW61/HetHqmIL
tD0c75UATi+gsTQnpwKPA/m38MGGyXFETr3xHXjilUPfIhmxO4ImuNJ0R95bZYhx
bLYmOZpVUcj8oz980An8HlIqSzrskQR6NiuEmikHkHc1/CpoNunrr8kQNPF6gxex
IrvXsKLUAuUqnNtcQWc/8Er5EN9+TdX6AOjUmKriVGbCInP1m/aC+DWH/+aJ/8aD
pKze6fe7OHh2BL9hxqIsmJAStIh4siRdLYTt8hKGmkdzOWnRAgMBAAGjggF/MIIB
ezASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwICBDAXBgNVHSUEEDAO
BgVngQUIAQYFZ4EFCAMwHQYDVR0OBBYEFGcJhvj5gV6TrfnJZOcUCtqZywotMB8G
A1UdIwQYMBaAFEv+JlqUwfYzw4NIJt3z5bBksqqVMHYGA1UdHwRvMG0wa6BpoGeG
ZWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL0F6dXJlJTIwVmly
dHVhbCUyMFRQTSUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIw
MjMuY3JsMIGDBggrBgEFBQcBAQR3MHUwcwYIKwYBBQUHMAKGZ2h0dHA6Ly93d3cu
bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvQXp1cmUlMjBWaXJ0dWFsJTIwVFBN
JTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMy5jcnQwDQYJ
KoZIhvcNAQEMBQADggIBAJPP3Z2z1zhzUS3qSRVgyoUVnaxCGuMHzPQAZuoPBVpz
wKnv4HqyjMgT8pBtQqxkqAsg7KiqbPfO97bMCHcuqkkfHjw8yg6IYt01RjUjVPKq
lrsY2iw7hFWNWr8SGMa10JdNYNyf5dxob5+mKAwEOhLzKNwq9rM/uIvZky77pNly
RLt55XEPfBMYdI9I8uQ5Uqmrw7mVJfERMfTBhSQF9BrcajAsaLcs7qEUyj0yUdJf
cgZkfCoUEUSPr3OwLHaYeV1J6VidhIYsYo53sXXal91d60NspYgei2nJFei/+R3E
SWnGbPBW+EQ4FbvZXxu57zUMX9mM7lC+GoXLvA6/vtKShEi9ZXl2PSnBQ/R2A7b3
AXyg4fmMLFausEk6OiuU8E/bvp+gPLOJ8YrX7SAJVuEn+koJaK5G7os5DMIh7/KM
l9cI9WxPwqoWjp4VBfrF4hDOCmKWrqtFUDQCML8qD8RTxlQKQtgeGAcNDfoAuL9K
VtSG5/iIhuyBEFYEHa3vRWbSaHCUzaHJsTmLcz4cp1VDdepzqZRVuErBzJKFnBXb
zRNW32EFmcAUKZImIsE5dgB7y7eiijf33VWNfWmK05fxzQziWFWRYlET4SVc3jMn
PBiY3N8BfK8EBOYbLvzo0qn2n3SAmPhYX3Ag6vbbIHd4Qc8DQKHRV0PB8D3jPGmD
-----END CERTIFICATE-----`)

// Validator for Azure confidential VM attestation using TDX.
type Validator struct {
	variant.AzureTDX
	*vtpm.Validator
	cfg *config.AzureTDX

	getter       trust.HTTPSGetter
	hclValidator hclAkValidator

	tcbOverride func(pcs.TcbInfo) pcs.TcbInfo
	log         attestation.Logger

	verifyAKCertEnabled bool
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

func (v *Validator) SetVerifyAKCertificate(enabled bool) {
	v.verifyAKCertEnabled = enabled
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
	if v.verifyAKCertEnabled {
		if err := v.verifyAKCertificate(instanceInfo, &pubArea); err != nil {
			return nil, fmt.Errorf("verifying AK certificate: %w", err)
		}
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
	// Ensure that the AK certificate is provided
	if len(instanceInfo.AkCert) == 0 {
		return errors.New("no AK certificate provided in instance info")
	}

	// Parse the AK certificate
	akCert, err := x509.ParseCertificate(instanceInfo.AkCert)
	if err != nil {
		return fmt.Errorf("parsing attestation key certificate: %w", err)
	}
	v.log.Debug(fmt.Sprintf("AK Certificate Subject: %s, Issuer: %s", akCert.Subject.String(), akCert.Issuer.String()))

	// Setup certificate pools
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	// Add all known Azure's root CAs
	// Microsoft RSA Devices Root CA 2021 (for older VMs)
	roots.AddCert(microsoftRSADevicesRoot2021)
	// Azure Virtual TPM Root Certificate Authority 2023 (for TDX and newer Trusted Launch)
	roots.AddCert(azureVirtualTPMRoot2023)

	// Add known Azure's intermediate CAs
	// Global Virtual TPM CA - 03 (for TDX VMs)
	intermediates.AddCert(globalVirtualTPMCA03)

	// Verify the certificate chain
	chains, err := akCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		v.log.Warn(fmt.Sprintf("Certificate chain verification failed: %v", err))
		return fmt.Errorf("verifying attestation key certificate chain: %w", err)
	}

	// Log the verified chain
	for i, chain := range chains {
		v.log.Debug(fmt.Sprintf("Verified chain %d:", i))
		for j, cert := range chain {
			v.log.Debug(fmt.Sprintf("  [%d] %s", j, cert.Subject.String()))
		}
	}

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
