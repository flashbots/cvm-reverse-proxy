// Package multimeasurements contains a helper to load a file with multiple measurements
// and compare provided measurements against them.
//
// Compatible with measurements data schema v2 (see measurements.json) as well as the
// legacy v1 schema.
package multimeasurements

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/measurements"
)

// MultiMeasurements holds several known measurements, and can check if
// given measurements match known ones.
type MultiMeasurements struct {
	Measurements []MeasurementsContainer
}

type MeasurementsContainer struct {
	MeasurementID   string         `json:"measurement_id"`
	AttestationType string         `json:"attestation_type"`
	Measurements    measurements.M `json:"measurements"`
}

type LegacyMultiMeasurements map[string]measurements.M

// Caps expansion of dstack-mr-gcp measurements
const maxGCPMeasurementContainers = 10_000

// Structure used by the dstack-mr-gcp output
type rawGCPMeasurements struct {
	MRTD  rawGCPMeasurementValues `json:"mrtd"`
	RTMR0 rawGCPMeasurementValues `json:"rtmr0"`
	RTMR1 rawGCPMeasurementValues `json:"rtmr1"`
	RTMR2 rawGCPMeasurementValues `json:"rtmr2"`
	RTMR3 rawGCPMeasurementValues `json:"rtmr3"`
}

type rawGCPMeasurementValues struct {
	values []string
	set    bool
}

// UnmarshalJSON accepts scalar or list measurement values from dstack-mr-gcp JSON
func (v *rawGCPMeasurementValues) UnmarshalJSON(data []byte) error {
	v.set = true

	var scalar string
	if err := json.Unmarshal(data, &scalar); err == nil {
		v.values = []string{scalar}
		return nil
	}

	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	v.values = values
	return nil
}

// New returns a MultiMeasurements instance, with the measurements
// loaded from a file or URL.
func New(path string) (m *MultiMeasurements, err error) {
	var data []byte
	if strings.HasPrefix(path, "http") {
		// load from URL
		resp, err := http.Get(path)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	} else {
		// load from file
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}

	return NewFromBytes(data)
}

// NewFromBytes returns a MultiMeasurements instance loaded from JSON bytes
func NewFromBytes(data []byte) (*MultiMeasurements, error) {
	m := &MultiMeasurements{}

	if err := json.Unmarshal(data, &m.Measurements); err == nil {
		return m, nil
	}

	var legacyData LegacyMultiMeasurements
	if err := json.Unmarshal(data, &legacyData); err == nil {
		for measurementID, measurements := range legacyData {
			container := MeasurementsContainer{
				MeasurementID:   measurementID,
				AttestationType: "azure-tdx",
				Measurements:    measurements,
			}
			m.Measurements = append(m.Measurements, container)
		}
		return m, nil
	}

	rawGCPContainers, err := parseRawGCPMeasurements(data)
	if err != nil {
		return nil, err
	}
	m.Measurements = rawGCPContainers
	return m, nil
}

// parseRawGCPMeasurements expands dstack-mr-gcp JSON into DCAP TDX measurement containers
func parseRawGCPMeasurements(data []byte) ([]MeasurementsContainer, error) {
	var raw rawGCPMeasurements
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing raw GCP measurements: %w", err)
	}

	mrtdValues, err := raw.requiredHexValues("mrtd", raw.MRTD)
	if err != nil {
		return nil, err
	}
	rtmr0Values, err := raw.requiredHexValues("rtmr0", raw.RTMR0)
	if err != nil {
		return nil, err
	}
	rtmr1Values, err := raw.requiredHexValues("rtmr1", raw.RTMR1)
	if err != nil {
		return nil, err
	}
	rtmr2Values, err := raw.requiredHexValues("rtmr2", raw.RTMR2)
	if err != nil {
		return nil, err
	}
	rtmr3Values, err := raw.optionalHexValues("rtmr3", raw.RTMR3)
	if err != nil {
		return nil, err
	}
	if len(rtmr3Values) == 0 {
		rtmr3Values = [][]byte{make([]byte, measurements.TDXMeasurementLength)}
	}

	total := len(mrtdValues) * len(rtmr0Values) * len(rtmr1Values) * len(rtmr2Values) * len(rtmr3Values)
	if total > maxGCPMeasurementContainers {
		return nil, fmt.Errorf("parsing raw GCP measurements: cartesian product of %d containers exceeds limit of %d", total, maxGCPMeasurementContainers)
	}

	containers := make([]MeasurementsContainer, 0, total)
	for mrtdIdx, mrtd := range mrtdValues {
		for rtmr0Idx, rtmr0 := range rtmr0Values {
			for rtmr1Idx, rtmr1 := range rtmr1Values {
				for rtmr2Idx, rtmr2 := range rtmr2Values {
					for rtmr3Idx, rtmr3 := range rtmr3Values {
						container := MeasurementsContainer{
							MeasurementID:   fmt.Sprintf("dstack-mr-gcp-%d-%d-%d-%d-%d", mrtdIdx, rtmr0Idx, rtmr1Idx, rtmr2Idx, rtmr3Idx),
							AttestationType: "dcap-tdx",
							Measurements: measurements.M{
								0: {Expected: mrtd, ValidationOpt: measurements.Enforce},
								1: {Expected: rtmr0, ValidationOpt: measurements.Enforce},
								2: {Expected: rtmr1, ValidationOpt: measurements.Enforce},
								3: {Expected: rtmr2, ValidationOpt: measurements.Enforce},
								4: {Expected: rtmr3, ValidationOpt: measurements.Enforce},
							},
						}
						containers = append(containers, container)
					}
				}
			}
		}
	}

	return containers, nil
}

// requiredHexValues decodes a required dstack-mr-gcp measurement field
func (rawGCPMeasurements) requiredHexValues(field string, values rawGCPMeasurementValues) ([][]byte, error) {
	if !values.set {
		return nil, fmt.Errorf("parsing raw GCP measurements: missing %q", field)
	}
	decoded, err := decodeRawGCPHexValues(field, values.values)
	if err != nil {
		return nil, err
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("parsing raw GCP measurements: %q must not be empty", field)
	}
	return decoded, nil
}

// optionalHexValues decodes an optional dstack-mr-gcp measurement field
func (rawGCPMeasurements) optionalHexValues(field string, values rawGCPMeasurementValues) ([][]byte, error) {
	if !values.set {
		return nil, nil
	}
	return decodeRawGCPHexValues(field, values.values)
}

// decodeRawGCPHexValues decodes and validates dstack-mr-gcp TDX measurement hex values
func decodeRawGCPHexValues(field string, values []string) ([][]byte, error) {
	decoded := make([][]byte, 0, len(values))
	for idx, value := range values {
		if value == "" {
			return nil, fmt.Errorf("parsing raw GCP measurements: %q[%d] must not be empty", field, idx)
		}
		bytes, err := hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("parsing raw GCP measurements: decoding %q[%d]: %w", field, idx, err)
		}
		if len(bytes) != measurements.TDXMeasurementLength {
			return nil, fmt.Errorf("parsing raw GCP measurements: %q[%d] has invalid length %d", field, idx, len(bytes))
		}
		decoded = append(decoded, bytes)
	}
	return decoded, nil
}

// Contains checks if the provided measurements match one of the known measurements. Any keys in the provided
// measurements which are not in the known measurements are ignored.
func (m *MultiMeasurements) Contains(measurements map[uint32][]byte) (found bool, foundMeasurement *MeasurementsContainer) {
	// For every known container, all known measurements match (and additional ones are ignored)
	for _, container := range m.Measurements {
		allMatch := true
		for key, value := range container.Measurements {
			if !bytes.Equal(value.Expected, measurements[key]) {
				allMatch = false
				break
			}
		}

		if allMatch {
			return true, &container
		}
	}

	return false, nil
}

func (m *MultiMeasurements) Count() (n uint32) {
	return uint32(len(m.Measurements))
}
