/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package tdx

import (
	"context"
	"encoding/json"
	"encoding/hex"
	"fmt"

	"github.com/flashbots/cvm-reverse-proxy/internal/attestation"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/measurements"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
	"github.com/flashbots/cvm-reverse-proxy/internal/config"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	ccpb "github.com/google/go-tdx-guest/proto/checkconfig"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// Validator is the TDX attestation validator.
type Validator struct {
	variant.QEMUTDX

	expected measurements.M

	log attestation.Logger
}

// NewValidator initializes a new TDX Validator.
func NewValidator(cfg *config.QEMUTDX, log attestation.Logger) *Validator {
	if log == nil {
		log = attestation.NOPLogger{}
	}

	return &Validator{
		expected: cfg.Measurements,
		log:      log,
	}
}

func hexToBytes(hexString string) []byte {
    bytes, err := hex.DecodeString(hexString)
    if err != nil {
        panic(err)
    }
    return bytes
}

// Validate validates the given attestation document using TDX attestation.
func (v *Validator) Validate(ctx context.Context, attDocRaw []byte, nonce []byte) (userData []byte, err error) {
	v.log.Info("Validating attestation document")
	defer func() {
		if err != nil {
			v.log.Warn(fmt.Sprintf("Failed to validate TDX attestation document: %s", err))
		}
	}()

	var attDoc tdxAttestationDocument
	if err := json.Unmarshal(attDocRaw, &attDoc); err != nil {
		return nil, fmt.Errorf("unmarshaling attestation document: %w", err)
	}

	err = writeRawQuoteToDisk(attDoc.RawQuote, false)
	if err != nil {
		return nil, fmt.Errorf("writing quote to disk: %w", err)
	}

	// Report data
	extraData := attestation.MakeExtraData(attDoc.UserData, nonce)
	// Ensure extraData is at least 64 bytes
	if len(extraData) < 64 {
		padding := make([]byte, 64-len(extraData))
		extraData = append(extraData, padding...)
	}

	// Assign the values of the flags to the corresponding proto fields
	config := &ccpb.Config{
		RootOfTrust: &ccpb.RootOfTrust{
			CheckCrl: true,
			GetCollateral: true,
		},
		Policy: &ccpb.Policy{
			HeaderPolicy: &ccpb.HeaderPolicy{
				MinimumQeSvn: 0,
				MinimumPceSvn: 0,
				QeVendorId: hexToBytes("939a7233f79c4ca9940a0db3957f0607"),
			},
			TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{
				TdAttributes:  hexToBytes("0000001000000000"),
				MrConfigId:    hexToBytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
				MrOwner:       hexToBytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
				MrOwnerConfig: hexToBytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
				ReportData:    extraData,
				MrTd:          v.expected[0].Expected,
				Rtmrs:         [][]byte{
							v.expected[1].Expected,
							v.expected[2].Expected,
							v.expected[3].Expected,
							v.expected[4].Expected,
				},
			},
		},
	}

	// config.Policy.TdQuoteBodyPolicy.MinimumTeeTcbSvn="" // skipping MinimumTeeTcbSvn as this is part of tcbinfo
	// considering skipping MRSEAM, the tdx module can only be provided by intel and there's already trust here. Also the TDX module svn is part of the tcbinfo check
	// yet still we might want to add a check for it at some point
	// config.Policy.TdQuoteBodyPolicy.MrSeam="bf70f5c1c2c1610bf2ddad348a88ebf6a550256e949e52122c743dc97cde50ccafad2fc5927d150f307fba3b8ca21872"

	quote, err := convertRawQuote(attDoc.RawQuote)
        if err != nil {
                return nil, fmt.Errorf("could not get quote from raw doc: %v", err)
        }

	// TCP Level
	options, err := verify.RootOfTrustToOptions(config.RootOfTrust)
	if err != nil {
		return nil, fmt.Errorf("converting root of trust to options: %w", err)
	}

	if err := verify.TdxQuote(quote, options); err != nil {
		return nil, fmt.Errorf("verifying TDX quote: %w", err)
	}

	// validate quote fields defined in policy
	opts, err := validate.PolicyToOptions(config.Policy)
	if err != nil {
		return nil, fmt.Errorf("converting policy to options: %v", err)
	}

	if err := validate.TdxQuote(quote, opts); err != nil {
		return nil, fmt.Errorf("error validating the TDX Quote: %v", err)
	}

	return attDoc.UserData, nil
}

func convertRawQuote(rawQuote []byte) (*pb.QuoteV4, error) {
	anyQuote, err := abi.QuoteToProto(rawQuote)
        if err != nil {
                return nil, fmt.Errorf("could not convert raw bytes to QuoteV4: %v", err)
        }
        quote, ok := anyQuote.(*pb.QuoteV4)
        if !ok {
                return nil, fmt.Errorf("Quote is not a QuoteV4")
        }

	return quote, nil
}

func parseDcapTDXAttestationMeasurements(quote *pb.QuoteV4) (map[uint32][]byte, error) {
	// Convert RTMRs and MRTD to map.
	tdMeasure := make(map[uint32][]byte, 5)
	tdMeasure[0] = quote.TdQuoteBody.MrTd[:]
	for idx := 0; idx < len(quote.TdQuoteBody.Rtmrs); idx++ {
		tdMeasure[uint32(idx+1)] = quote.TdQuoteBody.Rtmrs[idx][:]
	}

	return tdMeasure, nil
}

func ParseDcapTDXAttestationMeasurementsRaw(attDocRaw []byte) (map[uint32][]byte, error) {
	var attDoc tdxAttestationDocument
	if err := json.Unmarshal(attDocRaw, &attDoc); err != nil {
		return nil, fmt.Errorf("unmarshaling attestation document: %w", err)
	}

	quote, err := convertRawQuote(attDoc.RawQuote)
        if err != nil {
                return nil, fmt.Errorf("could not get quote from raw doc: %v", err)
        }

	return parseDcapTDXAttestationMeasurements(quote)
}
