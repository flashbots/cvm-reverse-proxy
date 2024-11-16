package common

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func getTestMeasurements() map[string]string {
	return map[string]string{
		"4": "1b8cd655f5ebdf50bedabfb5db6b896a0a7c56de54f318103a2de1e7cea57b6b",
		"9": "992465f922102234c196f596fdaba86ea16eaa4c264dc425ec26bc2d1c364472",
	}
}

// Expected measurements right from the source at https://measurements.builder.flashbots.net
var expectedMeasurementsJSON = `[{"measurement_id":"measurement-test-1","attestation_type":"azure-tdx","measurements":{"4":{"expected":"98ba2c602b62e67b8e0bd6c6676f12ade320a763e5e4564f62fd875a502dd651"},"9":{"expected":"e77938394412d83a8d4de52cdaf97df82a4d4059e1e7c4fc3c73581816cea496"},"11":{"expected":"0000000000000000000000000000000000000000000000000000000000000000"}}},{"measurement_id":"cvm-image-azure-tdx.rootfs-20241107200854.wic.vhd","attestation_type":"azure-tdx","measurements":{"4":{"expected":"1b8cd655f5ebdf50bedabfb5db6b896a0a7c56de54f318103a2de1e7cea57b6b"},"9":{"expected":"992465f922102234c196f596fdaba86ea16eaa4c264dc425ec26bc2d1c364472"}}}]`

func TestExpectedMeasurements(t *testing.T) {
	// Load expected measurements from provided JSON string
	m := ExpectedMeasurements{}
	err := json.Unmarshal([]byte(expectedMeasurementsJSON), &m.Measurements)
	require.NoError(t, err)

	// Ensure that two known measurements are loaded
	require.Len(t, m.Measurements, 2)

	// Ensure matching keys work and additional fields are ignored
	testMeasurement := getTestMeasurements() // matches known measurements (which require values 4 and 9)
	testMeasurement["11"] = "1234"           // additional key to check that it is ignored
	exists, name := m.Contains(testMeasurement)
	require.True(t, exists)
	require.Equal(t, "cvm-image-azure-tdx.rootfs-20241107200854.wic.vhd", name)

	// Ensure that all known keys need to match
	testMeasurement = getTestMeasurements() // matches known measurements (which require values 4 and 9)
	delete(testMeasurement, "4")            // remove a required key, to make it fail the check
	exists, _ = m.Contains(testMeasurement)
	require.False(t, exists)
}
