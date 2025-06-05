/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package tdx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/flashbots/cvm-reverse-proxy/internal/attestation"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"

	"github.com/google/go-tdx-guest/client"
)

var logDcapQuote bool

type tdxAttestationDocument struct {
	// RawQuote is the raw TDX quote.
	RawQuote []byte
	// UserData is the user data that was passed to the enclave and was included in the quote.
	UserData []byte
}

// Issuer is the TDX attestation issuer.
type Issuer struct {
	variant.QEMUTDX

	log attestation.Logger
}

// NewIssuer initializes a new TDX Issuer.
func NewIssuer(log attestation.Logger) *Issuer {
	if log == nil {
		log = attestation.NOPLogger{}
	}
	return &Issuer{
		log: log,
	}
}

func SetLogDcapQuote(logQuote bool) {
	logDcapQuote = logQuote
	if logDcapQuote {
		// Create local folder "quotes" if it doesn't exist
		if _, err := os.Stat("quotes"); os.IsNotExist(err) {
			os.Mkdir("quotes", os.ModePerm)
		}
	}
}

// Issue issues a TDX attestation document.
func (i *Issuer) Issue(_ context.Context, userData []byte, nonce []byte) (attDoc []byte, err error) {
	i.log.Info("Issuing attestation statement")
	defer func() {
		if err != nil {
			i.log.Warn(fmt.Sprintf("Failed to issue attestation document: %s", err))
		}
	}()

	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("get quote provider: %w", err)
	}

	var checkedUserData [64]byte
	copy(checkedUserData[:], attestation.MakeExtraData(userData, nonce))

	quote, err := qp.GetRawQuote(checkedUserData)
	if err != nil {
		return nil, fmt.Errorf("generating quote: %w", err)
	}

	err = writeRawQuoteToDisk(quote, true)
	if err != nil {
		return nil, fmt.Errorf("writing quote to disk: %w", err)
	}

	rawAttDoc, err := json.Marshal(tdxAttestationDocument{
		RawQuote: quote,
		UserData: userData,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling attestation document: %w", err)
	}

	return rawAttDoc, nil
}

func writeRawQuoteToDisk(RawQuote []byte, isIssued bool) error {
	if !logDcapQuote {
		return nil
	}

	timestamp := time.Now().Format("20060102_150405")
	quoteType := "issued"
	if !isIssued {
		quoteType = "received"
	}

	fileName := fmt.Sprintf("quotes/quote_%s_%s.dat", quoteType, timestamp)
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(RawQuote)
	if err != nil {
		return err
	}

	return nil
}
