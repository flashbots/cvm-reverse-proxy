package multimeasurements

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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

const rawGCPChunkedJSON = `{
  "rtmr1": "cdf855b56d27967473b885164b3910ab4d81f3db0bd50e114593bd5fd91cf55760de7776c93f4724cefeaf5ac0843e62",
  "rtmr2": "438337a98c597535940941a3d9913e04a76d84e4ebf69dbb89e1addc8bae7183579685f0ef3144875dba7d933d9dcabf",
  "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "rtmr0": [
    "c07820997dc2a5e1cc67b05e89852c1a72289e0ec82034bee5b3605cd759328853a758a346522651956afe9222914235",
    "c6975b4a5d66fd88bce4d449ed161e0800ce0f5bcd6a3246f2c83407e230474ff56e6e8d5bc9e9d95cf692d458257954",
    "8256ae5bb15489ebb0181f9935fe00625751e879d4e3b0a111aaba48da31e5cdd82f379cf4b97411618b02ce1deba1fd",
    "46af3396ed9969f670f69142f7b74514598b0f25bb66fc3094402c2de37f4f7493d83cc0860416d3e50f7dda1c34f658",
    "c0f93df02880d6c1dc1a5104e04ef691bc41cdc9da49f8834cc1cdc10acdb557758371d19d2466b560be7a66643953fd",
    "6927bd0230ca2dba4ad21ee68c1f7e018660d5ad6a99e185eac8adc1f05dd6eeb10178d2a744d22cd14b8945b454712b",
    "b90ca4eb0badc04128035ad62f1d1e792f1ca40c99ce25e3cce13f8167eb6265e890c65097518e9f8f5af91519d60d73",
    "c3940a1a1f6709fed6d90c34698cb91767fa6261f4469fdcf6da5e36c6f2493fdfd34bc2d1a9f726a17ed88a79b33561",
    "8530903ec5cb9aad1737c2bf0e9df958ec0a3ede63fe556415990192b4def86a50d8f6869b6283141b13dd4848b0cea2",
    "9efb7193464610d63fbd948901998eda998b3e47e9a0abb72857ba948dcbacd3a17ee75e5081455dccaae208b8294bd9",
    "5c942d2f4a08acd594b7d8914362835dcbb12994aedc2128abecf5585807cb8886faf7b9b32611cd4e63eac269632560",
    "284f209fece0d49331f2e411c46f6debc3be698bd8587264c90ab0dbdf651046aef3badaae9a7983ea0855a7dabdfa00",
    "8d5f7f704ccba0a63157f1ec1214c7f043005b045adae261e0581951965a96350d6196f38751b5dd0e72fca181817efa",
    "123ad184172b44083b191b12557f3c923416d8e654ffb390736db331ff2a5bce6c89d14d62cf70e113b98d8f13e78519",
    "8ae3d7af48afa0f30fd700a58ca84cd5e0054fbe011d9ed228e30a17db456987e63c6dfd71437aac33ffb9d796088d70",
    "3fdfcb2bbf25c9e535f7e4724b1cee79666824cab1565f985d2e1e0218818d538cf6f3bfa5c623c13d6226ae51ea8cd6",
    "640b92712990cc8aab4f3786611a8acc3180525abd42a31c06eb7611b8c54a72247dfe8a7a93d3c922f771797a7932de",
    "7c8fc1dd62391d416ac64174b833f821b59738d816d96168483300127608e0cf3345840b5bd9325c125dd6b2f595f1b0",
    "a191d8250215e05e31fc42fa00f4b7a8729e1fb83b3dacb3def3989b9eaa3f8d199b96759477ce20bbd47c909b6b984c",
    "633eeb1778affe65d1b3633527395763602c06e9d7aea52a2a6d5073c33ee1fe78f3a83aeb58edd036de681eee3d1f0f",
    "b372a4eac4561e3a8d92028a38e8860a63d7e69c7fcab250aa49d1c951c94b49d0abbe87c353fcd14651f64ac5dde055",
    "90d7dbdb795d66669ff44aff1f8ea0de13f5362f1dec68f17fca60364fcc019de18b246c9e173c09102360442dba3261",
    "8292abcf17f665c5f63e158a5fd7f2e160ac5b5ae4811532d93c3b5f38a53adebebddaf531aca4ef91d9fb68fb4312a8",
    "e1d0235496f93f9475bf0b26d33da5c15831cfc94104d6bea7ab82db027c5f1e917d47dda6953eefae7dcb20ab6f75c4"
  ],
  "mrtd": [
    "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694",
    "8370d8f6d02f2d13e211e91c93fde923049522b241425a29a7bf0071ef49b250af4ef49d852fa3e10065d1b51dfce8fb",
    "feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162"
  ],
	"mrconfigid": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"xfam": "e700060000000000",
	"tdattributes": "0000001000000000"
}`

// rawGCPScalarJSON returns a single-value dstack-mr-gcp fixture
func rawGCPScalarJSON() []byte {
	return []byte(`{
  "mrtd": ["` + strings.Repeat("11", 48) + `"],
  "rtmr0": ["` + strings.Repeat("22", 48) + `"],
  "rtmr1": "` + strings.Repeat("33", 48) + `",
  "rtmr2": "` + strings.Repeat("44", 48) + `",
  "mr_aggregated": "` + strings.Repeat("aa", 32) + `",
  "mr_image": "` + strings.Repeat("bb", 32) + `"
}`)
}

// writeMeasurementsFile writes a temporary measurements fixture
func writeMeasurementsFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "measurements.json")
	err := os.WriteFile(path, data, 0644)
	require.NoError(t, err)
	return path
}

// TestMultiMeasurementsV2 tests the v2 data schema
func TestMultiMeasurementsV2(t *testing.T) {
	// Load expected measurements from JSON file (in V2 format)
	m, err := New("../measurements.json")
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

	// Check for another set of known measurements (dcap-tdx-dummy)
	testMeasurements = TestMeasurements{
		0: mustBytesFromHex("47a1cc074b914df8596bad0ed13d50d561ad1effc7f7cc530ab86da7ea49ffc03e57e7da829f8cba9c629c3970505323"),
		1: mustBytesFromHex("da6e07866635cb34a9ffcdc26ec6622f289e625c42c39b320f29cdf1dc84390b4f89dd0b073be52ac38ca7b0a0f375bb"),
		2: mustBytesFromHex("a7157e7c5f932e9babac9209d4527ec9ed837b8e335a931517677fa746db51ee56062e3324e266e3f39ec26a516f4f71"),
		3: mustBytesFromHex("e63560e50830e22fbc9b06cdce8afe784bf111e4251256cf104050f1347cd4ad9f30da408475066575145da0b098a124"),
		4: mustBytesFromHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
	}
	exists, foundMeasurement = m.Contains(testMeasurements)
	require.True(t, exists)
	require.Equal(t, "dcap-tdx-dummy", foundMeasurement.MeasurementID)
}

func TestMultiMeasurementsV1(t *testing.T) {
	// Load expected measurements from JSON file
	m, err := New(writeMeasurementsFile(t, measurementsV1JSON))
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

// TestMultiMeasurementsRawGCPScalar tests scalar-valued dstack-mr-gcp measurements
func TestMultiMeasurementsRawGCPScalar(t *testing.T) {
	m, err := New(writeMeasurementsFile(t, rawGCPScalarJSON()))
	require.NoError(t, err)
	require.Len(t, m.Measurements, 1)

	container := m.Measurements[0]
	require.Equal(t, "dcap-tdx", container.AttestationType)
	require.Equal(t, mustBytesFromHex(strings.Repeat("11", 48)), container.Measurements[0].Expected)
	require.Equal(t, mustBytesFromHex(strings.Repeat("22", 48)), container.Measurements[1].Expected)
	require.Equal(t, mustBytesFromHex(strings.Repeat("33", 48)), container.Measurements[2].Expected)
	require.Equal(t, mustBytesFromHex(strings.Repeat("44", 48)), container.Measurements[3].Expected)
	require.Equal(t, mustBytesFromHex(strings.Repeat("00", 48)), container.Measurements[4].Expected)

	exists, foundMeasurement := m.Contains(TestMeasurements{
		0: mustBytesFromHex(strings.Repeat("11", 48)),
		1: mustBytesFromHex(strings.Repeat("22", 48)),
		2: mustBytesFromHex(strings.Repeat("33", 48)),
		3: mustBytesFromHex(strings.Repeat("44", 48)),
		4: mustBytesFromHex(strings.Repeat("00", 48)),
	})
	require.True(t, exists)
	require.Equal(t, container.MeasurementID, foundMeasurement.MeasurementID)
}

// TestMultiMeasurementsRawGCPChunked tests list-valued dstack-mr-gcp measurements
func TestMultiMeasurementsRawGCPChunked(t *testing.T) {
	m, err := New(writeMeasurementsFile(t, []byte(rawGCPChunkedJSON)))
	require.NoError(t, err)
	require.Len(t, m.Measurements, 72)

	exists, foundMeasurement := m.Contains(TestMeasurements{
		0: mustBytesFromHex("feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162"),
		1: mustBytesFromHex("c6975b4a5d66fd88bce4d449ed161e0800ce0f5bcd6a3246f2c83407e230474ff56e6e8d5bc9e9d95cf692d458257954"),
		2: mustBytesFromHex("cdf855b56d27967473b885164b3910ab4d81f3db0bd50e114593bd5fd91cf55760de7776c93f4724cefeaf5ac0843e62"),
		3: mustBytesFromHex("438337a98c597535940941a3d9913e04a76d84e4ebf69dbb89e1addc8bae7183579685f0ef3144875dba7d933d9dcabf"),
		4: mustBytesFromHex(strings.Repeat("00", 48)),
	})
	require.True(t, exists)
	require.Equal(t, "dcap-tdx", foundMeasurement.AttestationType)
}

// TestMultiMeasurementsRawGCPMalformed tests malformed dstack-mr-gcp measurements
func TestMultiMeasurementsRawGCPMalformed(t *testing.T) {
	_, err := New(writeMeasurementsFile(t, []byte(`{
  "mrtd": ["not-hex"],
  "rtmr0": ["`+strings.Repeat("22", 48)+`"],
  "rtmr1": "`+strings.Repeat("33", 48)+`",
  "rtmr2": "`+strings.Repeat("44", 48)+`"
}`)))
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing raw GCP measurements")
}

// TestMultiMeasurementsRawGCPCartesianLimit tests that oversized cartesian products are rejected
func TestMultiMeasurementsRawGCPCartesianLimit(t *testing.T) {
	// 101 values for both mrtd and rtmr0 -> 101*101 = 10,201 > 10,000 limit
	manyValues := make([]string, 101)
	for i := range manyValues {
		manyValues[i] = `"` + strings.Repeat("ab", 48) + `"`
	}
	valuesJSON := "[" + strings.Join(manyValues, ",") + "]"

	_, err := NewFromBytes([]byte(`{
  "mrtd": ` + valuesJSON + `,
  "rtmr0": ` + valuesJSON + `,
  "rtmr1": "` + strings.Repeat("33", 48) + `",
  "rtmr2": "` + strings.Repeat("44", 48) + `"
}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds limit")
}
