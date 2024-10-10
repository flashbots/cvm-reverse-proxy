/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package tdx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/flashbots/cvm-reverse-proxy/internal/attestation"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/measurements"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
	"github.com/flashbots/cvm-reverse-proxy/internal/config"

	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/abi"
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

	// TCP Level
	options := &verify.Options{CheckRevocations: true, GetCollateral: true}
	if err := verify.RawTdxQuote(attDoc.RawQuote, options); err != nil {
		return nil, fmt.Errorf("verifying TDX quote: %w", err)
	}

	quote, err := convertRawQuote(attDoc.RawQuote)
        if err != nil {
                return nil, fmt.Errorf("could not get quote from raw doc: %v", err)
        }

	// Report data
	extraData := attestation.MakeExtraData(attDoc.UserData, nonce)
	if !attestation.CompareExtraData(quote.TdQuoteBody.ReportData[:], extraData) {
		return nil, fmt.Errorf("report data in TDX quote does not match provided nonce")
	}

	tdMeasure, err := parseDcapTDXAttestationMeasurements(quote)
	if err != nil {
		return nil, fmt.Errorf("could not parse DCAP attestation measurements: %v", err)
	}

	// Verify the quote against the expected measurements.
	warnings, errs := v.expected.Compare(tdMeasure)
	for _, warning := range warnings {
		v.log.Warn(warning)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("measurement validation failed:\n%w", errors.Join(errs...))
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
