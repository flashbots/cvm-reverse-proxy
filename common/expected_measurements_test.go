package common

import (
	"encoding/hex"
	"os"
	"path/filepath"
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

// Measurements V1 (legacy) JSON (from https://github.com/flashbots/cvm-reverse-proxy/blob/837588b9f87ee49d1bb6dca4712a1c2844eb1ecc/measurements.json)
var measurementsV1JSON = []byte(`{"azure-tdx-example":{"11":{"expected":"efa43e0beff151b0f251c4abf48152382b1452b4414dbd737b4127de05ca31f7"},"12":{"expected":"0000000000000000000000000000000000000000000000000000000000000000"},"13":{"expected":"0000000000000000000000000000000000000000000000000000000000000000"},"15":{"expected":"0000000000000000000000000000000000000000000000000000000000000000"},"4":{"expected":"ea92ff762767eae6316794f1641c485d4846bc2b9df2eab6ba7f630ce6f4d66f"},"8":{"expected":"0000000000000000000000000000000000000000000000000000000000000000"},"9":{"expected":"c9f429296634072d1063a03fb287bed0b2d177b0a504755ad9194cffd90b2489"}},"dcap-tdx-example":{"0":{"expected":"5d56080eb9ef8ce0bbaf6bdcdadeeb06e7c5b0a4d1ec16be868a85a953babe0c5e54d01c8e050a54fe1ca078372530d2"},"1":{"expected":"4216e925f796f4e282cfa6e72d4c77a80560987afa29155a61fdc33adb80eab0d4112abd52387e5e25a60deefb8a5287"},"2":{"expected":"4274fefb79092c164000b571b64ecb432fa2357adb421fd1c77a867168d7d7f7fe82796d1eba092c7bab35cf43f5ec55"},"3":{"expected":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},"4":{"expected":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}}}`)

// TestExpectedMeasurementsV2 tests the v2 data schema
func TestExpectedMeasurementsV2(t *testing.T) {
	// Load expected measurements from JSON file (in V2 format)
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

func TestExpectedMeasurementsV1(t *testing.T) {
	tempDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tempDir, "measurements.json"), measurementsV1JSON, 0644)
	require.NoError(t, err)

	// Load expected measurements from JSON file
	m, err := NewExpectedMeasurementsFromFile(filepath.Join(tempDir, "measurements.json"))
	require.NoError(t, err)
	require.Len(t, m.Measurements, 2)

	testMeasurements := TestMeasurements{
		0: mustBytesFromHex("5d56080eb9ef8ce0bbaf6bdcdadeeb06e7c5b0a4d1ec16be868a85a953babe0c5e54d01c8e050a54fe1ca078372530d2"),
		1: mustBytesFromHex("4216e925f796f4e282cfa6e72d4c77a80560987afa29155a61fdc33adb80eab0d4112abd52387e5e25a60deefb8a5287"),
		2: mustBytesFromHex("4274fefb79092c164000b571b64ecb432fa2357adb421fd1c77a867168d7d7f7fe82796d1eba092c7bab35cf43f5ec55"),
		3: mustBytesFromHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		4: mustBytesFromHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
	}
	exists, foundMeasurement := m.Contains(testMeasurements)
	require.True(t, exists)
	require.Equal(t, "dcap-tdx-example", foundMeasurement.MeasurementID)
}
