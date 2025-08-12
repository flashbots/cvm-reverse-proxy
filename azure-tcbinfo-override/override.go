package azure_tcbinfo_override

import (
	"slices"

	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	azure_tdx "github.com/flashbots/cvm-reverse-proxy/internal/attestation/azure/tdx"

	"github.com/google/go-tdx-guest/pcs"
)

var expectedV6SGXTCBComponents = []byte{2, 2, 2, 2, 3, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0}

func OverrideV6InstanceOutdatedSEAMLoader(tcbInfo pcs.TcbInfo) pcs.TcbInfo {
	if tcbInfo.Fmspc == "90c06f000000" {
		if len(tcbInfo.TcbLevels) == 2 && slices.EqualFunc(tcbInfo.TcbLevels[0].Tcb.SgxTcbcomponents, expectedV6SGXTCBComponents, func(tc pcs.TcbComponent, b byte) bool { return tc.Svn == b }) {
			// OS/VMM SEAMLDR ACM
			tcbInfo.TcbLevels[0].Tcb.SgxTcbcomponents[7].Svn = 3
			return tcbInfo
		}
	}

	return tcbInfo
}

func OverrideAzureValidatorsForV6SEAMLoader(validators []atls.Validator) {
	for _, validator := range validators {
		if azureTdxValidator, ok := validator.(*azure_tdx.Validator); ok {
			azureTdxValidator.SetTcbOverride(OverrideV6InstanceOutdatedSEAMLoader)
		}
	}
}
