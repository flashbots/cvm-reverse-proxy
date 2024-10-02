package proxy

import (
	"context"
	"encoding/asn1"

	"cvm-reverse-proxy/internal/atls"
)

// Validator for Azure confidential VM attestation using TDX which accepts multiple measurements
type MultiValidator struct {
	oid        asn1.ObjectIdentifier
	validators []atls.Validator
}

// NewMultiValidator returns a new Validator for Azure confidential VM attestation using TDX which accepts multiple measurements
func NewMultiValidator(validators []atls.Validator) *MultiValidator {
	for _, v := range validators {
		if !v.OID().Equal(validators[0].OID()) {
			// This is not an error! This is a bug!
			panic("validators with mismatching OIDs passed in!")
		}
	}
	return &MultiValidator{
		oid:        validators[0].OID(),
		validators: validators,
	}
}

func (v *MultiValidator) OID() asn1.ObjectIdentifier {
	return v.oid
}

func (v *MultiValidator) Validate(ctx context.Context, attDocRaw []byte, nonce []byte) (userData []byte, err error) {
	for _, validator := range v.validators {
		if userData, err = validator.Validate(ctx, attDocRaw, nonce); err == nil {
			return
		}
	}

	return
}
