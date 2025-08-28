package azure_tcbinfo_override

import (
	"log/slog"

	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	azure_tdx "github.com/flashbots/cvm-reverse-proxy/internal/attestation/azure/tdx"
	"github.com/flashbots/cvm-reverse-proxy/proxy"

	"github.com/google/go-tdx-guest/pcs"
)

func OverrideV6InstanceOutdatedSEAMLoader(log *slog.Logger, tcbInfo pcs.TcbInfo) pcs.TcbInfo {
	if tcbInfo.Fmspc == azure_tdx.AZURE_V6_BAD_FMSPC {
		for l, tcbLevel := range tcbInfo.TcbLevels {
			if tcbLevel.TcbStatus == pcs.TcbComponentStatusUpToDate {
				if tcbLevel.Tcb.SgxTcbcomponents[7].Svn > 3 {
					log.Debug("overriding tcb info to allow outdated Azure v6 SEAM loader")
					tcbInfo.TcbLevels[l].Tcb.SgxTcbcomponents[7].Svn = 3
				}
			}
		}
	}

	return tcbInfo
}

func OverrideAzureValidatorsForV6SEAMLoader(log *slog.Logger, validators []atls.Validator) {
	for _, validator := range validators {
		if multiValidator, ok := validator.(*proxy.MultiValidator); ok {
			OverrideAzureValidatorsForV6SEAMLoader(log, multiValidator.Validators())
		}
		if azureTdxValidator, ok := validator.(*azure_tdx.Validator); ok {
			log.Info("set tcb overide for Azure TDX validator")
			azureTdxValidator.SetTcbOverride(func(tcbInfo pcs.TcbInfo) pcs.TcbInfo { return OverrideV6InstanceOutdatedSEAMLoader(log, tcbInfo) })
		}
	}
}
