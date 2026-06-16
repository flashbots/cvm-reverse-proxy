package proxy

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	"github.com/stretchr/testify/require"
)

// TestCreateAttestationValidatorsFromRawGCPMeasurementFile tests dstack-mr-gcp validator setup
func TestCreateAttestationValidatorsFromRawGCPMeasurementFile(t *testing.T) {
	measurementsJSON := []byte(`{
  "mrtd": ["` + strings.Repeat("11", 48) + `"],
  "rtmr0": ["` + strings.Repeat("22", 48) + `"],
  "rtmr1": "` + strings.Repeat("33", 48) + `",
  "rtmr2": "` + strings.Repeat("44", 48) + `",
  "rtmr3": "` + strings.Repeat("00", 48) + `"
}`)
	path := filepath.Join(t.TempDir(), "measurements.json")
	err := os.WriteFile(path, measurementsJSON, 0644)
	require.NoError(t, err)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	validators, err := CreateAttestationValidatorsFromFile(log, path)
	require.NoError(t, err)
	require.Len(t, validators, 1)

	multiValidator, ok := validators[0].(interface {
		Validators() []atls.Validator
	})
	require.True(t, ok)
	require.Len(t, multiValidator.Validators(), 1)
}
