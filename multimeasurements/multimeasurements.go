// Package multimeasurements contains a helper to load a file with multiple measurements
// and compare provided measurements against them.
//
// Compatible with measurements data schema v2 (see measurements.json) as well as the
// legacy v1 schema.
package multimeasurements

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/measurements"
	"github.com/flashbots/cvm-reverse-proxy/internal/encoding"
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

// Structure used by the dstack-mr-gcp output. mrtd and rtmr0 hold one entry per
// possible value; rtmr1-3 are single values.
type rawGCPMeasurements struct {
	MRTD  []encoding.HexBytes `json:"mrtd"`
	RTMR0 []encoding.HexBytes `json:"rtmr0"`
	RTMR1 encoding.HexBytes   `json:"rtmr1"`
	RTMR2 encoding.HexBytes   `json:"rtmr2"`
	RTMR3 encoding.HexBytes   `json:"rtmr3"`
}

// New returns a MultiMeasurements instance, with the measurements
// loaded from a file or URL.
func New(path string) (*MultiMeasurements, error) {
	if strings.HasPrefix(path, "http") {
		resp, err := http.Get(path)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return NewFromBytes(data)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
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

	if raw.RTMR3 == nil {
		raw.RTMR3 = make(encoding.HexBytes, measurements.TDXMeasurementLength)
	}
	if err := validateGCPMeasurements(raw); err != nil {
		return nil, err
	}

	total := len(raw.MRTD) * len(raw.RTMR0)
	if total > maxGCPMeasurementContainers {
		return nil, fmt.Errorf("parsing raw GCP measurements: cartesian product of %d containers exceeds limit of %d", total, maxGCPMeasurementContainers)
	}

	containers := make([]MeasurementsContainer, 0, total)
	for mrtdIdx, mrtd := range raw.MRTD {
		for rtmr0Idx, rtmr0 := range raw.RTMR0 {
			containers = append(containers, MeasurementsContainer{
				MeasurementID:   fmt.Sprintf("dstack-mr-gcp-%d-%d", mrtdIdx, rtmr0Idx),
				AttestationType: "dcap-tdx",
				Measurements: measurements.M{
					0: {Expected: mrtd, ValidationOpt: measurements.Enforce},
					1: {Expected: rtmr0, ValidationOpt: measurements.Enforce},
					2: {Expected: raw.RTMR1, ValidationOpt: measurements.Enforce},
					3: {Expected: raw.RTMR2, ValidationOpt: measurements.Enforce},
					4: {Expected: raw.RTMR3, ValidationOpt: measurements.Enforce},
				},
			})
		}
	}

	return containers, nil
}

// validateGCPMeasurements checks that all dstack-mr-gcp fields are present and have valid TDX measurement lengths
func validateGCPMeasurements(raw rawGCPMeasurements) error {
	lists := map[string][]encoding.HexBytes{"mrtd": raw.MRTD, "rtmr0": raw.RTMR0}
	for field, values := range lists {
		if len(values) == 0 {
			return fmt.Errorf("parsing raw GCP measurements: %q must not be empty", field)
		}
		for idx, value := range values {
			if len(value) != measurements.TDXMeasurementLength {
				return fmt.Errorf("parsing raw GCP measurements: %q[%d] has invalid length %d", field, idx, len(value))
			}
		}
	}

	scalars := map[string]encoding.HexBytes{"rtmr1": raw.RTMR1, "rtmr2": raw.RTMR2, "rtmr3": raw.RTMR3}
	for field, value := range scalars {
		if len(value) != measurements.TDXMeasurementLength {
			return fmt.Errorf("parsing raw GCP measurements: %q has invalid length %d", field, len(value))
		}
	}

	return nil
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
