package common

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMeasurements is kept simple: map[pcr]measurement
type TestMeasurements map[uint32][]byte

func mustBytesFromHex(hexValue string) []byte {
	bytes, err := hex.DecodeString(hexValue)
	if err != nil {
		panic(err)
	}
	return bytes
}

// TestExpectedMeasurementsV2 tests the v2 data schema
func TestExpectedMeasurementsV2(t *testing.T) {
	// Load expected measurements from JSON file
	m, err := NewExpectedMeasurementsFromFile("../measurements.json")
	require.NoError(t, err)
	require.Len(t, m.Measurements, 3)

	// Setup test measurements (matching cvm-image-azure-tdx.rootfs-20241107200854.wic.vhd)
	testMeasurements := TestMeasurements{
		4: mustBytesFromHex("1b8cd655f5ebdf50bedabfb5db6b896a0a7c56de54f318103a2de1e7cea57b6b"),
		9: mustBytesFromHex("992465f922102234c196f596fdaba86ea16eaa4c264dc425ec26bc2d1c364472"),
	}

	// Ensure matching entries works, and that additional fields are ignored
	testMeasurements[11] = testMeasurements[4]
	exists, foundMeasurement := m.Contains(testMeasurements)
	require.True(t, exists)
	require.Equal(t, "cvm-image-azure-tdx.rootfs-20241107200854.wic.vhd", foundMeasurement.MeasurementID)
	require.Equal(t, "azure-tdx", foundMeasurement.AttestationType)

	// Ensure check fails with a missing required key
	delete(testMeasurements, 4)
	exists, _ = m.Contains(testMeasurements)
	require.False(t, exists)

	// Double-check it works again
	testMeasurements[4] = testMeasurements[11]
	exists, _ = m.Contains(testMeasurements)
	require.True(t, exists)

	// Any changed value should make it fail
	testMeasurements[4] = testMeasurements[9]
	exists, _ = m.Contains(testMeasurements)
	require.False(t, exists)

	// Check for another set of known measurements (dcap-tdx-example)
	testMeasurements = TestMeasurements{
		0: mustBytesFromHex("5d56080eb9ef8ce0bbaf6bdcdadeeb06e7c5b0a4d1ec16be868a85a953babe0c5e54d01c8e050a54fe1ca078372530d2"),
		1: mustBytesFromHex("4216e925f796f4e282cfa6e72d4c77a80560987afa29155a61fdc33adb80eab0d4112abd52387e5e25a60deefb8a5287"),
		2: mustBytesFromHex("4274fefb79092c164000b571b64ecb432fa2357adb421fd1c77a867168d7d7f7fe82796d1eba092c7bab35cf43f5ec55"),
		3: mustBytesFromHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		4: mustBytesFromHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
	}
	exists, foundMeasurement = m.Contains(testMeasurements)
	require.True(t, exists)
	require.Equal(t, "dcap-tdx-example-02", foundMeasurement.MeasurementID)
}
