// Package multimeasurements contains a helper to load a file with multiple measurements
// and compare provided measurements against them.
//
// Compatible with measurements data schema v2 (see measurements.json) as well as the
// legacy v1 schema.
package multimeasurements

import (
	"bytes"
	"encoding/json"
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

	m = &MultiMeasurements{}

	// Try to load the v2 data schema, if that fails fall back to legacy v1 schema
	if err = json.Unmarshal(data, &m.Measurements); err != nil {
		var legacyData LegacyMultiMeasurements
		err = json.Unmarshal(data, &legacyData)
		for measurementID, measurements := range legacyData {
			container := MeasurementsContainer{
				MeasurementID:   measurementID,
				AttestationType: "azure-tdx",
				Measurements:    measurements,
			}
			m.Measurements = append(m.Measurements, container)
		}
	}

	return m, err
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
