package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-tdx-guest/client"
	"github.com/konvera/geth-sev/constellation/attestation"
	"github.com/konvera/geth-sev/constellation/attestation/variant"
)

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

// Issue issues a TDX attestation document.
func (i *Issuer) Issue(_ context.Context, userData []byte, nonce []byte) (attDoc []byte, err error) {
	i.log.Info("Issuing attestation statement")
	defer func() {
		if err != nil {
			i.log.Warn(fmt.Sprintf("Failed to issue attestation document: %s", err))
		}
	}()

	var checkedUserData [64]byte
	copy(checkedUserData[:], attestation.MakeExtraData(userData, nonce))

	qp := &client.LinuxConfigFsQuoteProvider{}
	quote, err := qp.GetRawQuote(checkedUserData)
	if err != nil {
		return nil, fmt.Errorf("generating quote: %w", err)
	}

	rawAttDoc, err := json.Marshal(struct {
		RawQuote []byte
		UserData []byte
	}{
		RawQuote: quote,
		UserData: userData,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling attestation document: %w", err)
	}

	return rawAttDoc, nil
}
