package proxy

import (
	"context"
	"encoding/asn1"

	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
)

// MultiValidator is a validator which accepts multiple measurements for the same type of attestation
type MultiValidator struct {
	oid        asn1.ObjectIdentifier
	validators []atls.Validator
}

// NewMultiValidator returns a new Validator for Azure confidential VM attestation using TDX which accepts multiple measurements
func NewMultiValidator(validators []atls.Validator) *MultiValidator {
	if len(validators) == 0 {
		// This is not an error! This is a bug!
		panic("empty validators list passed in!")
	}

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

func (v *MultiValidator) Append(nv atls.Validator) {
	if !v.oid.Equal(nv.OID()) {
		// This is not an error! This is a bug!
		panic("validators with mismatching OIDs passed in!")
	}
	v.validators = append(v.validators, nv)
}

func (v *MultiValidator) OID() asn1.ObjectIdentifier {
	return v.oid
}

func (v *MultiValidator) Validate(ctx context.Context, attDocRaw, nonce []byte) (userData []byte, err error) {
	for _, validator := range v.validators {
		if userData, err = validator.Validate(ctx, attDocRaw, nonce); err == nil {
			return
		}
	}

	return
}
