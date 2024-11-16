package common

//
// Helper to load expected measurements from a file or URL, and compare
// provided measurements against them.
//
// Internally this uses the measurements data schema v2 (as served by
// https://measurements.builder.flashbots.net), but is also backwards
// compatible with v1 (i.e. measurements.json used by cvm-proxy).
//
// Data schema v2:
//
//   [
//       {
//           "measurement_id": "cvm-image-azure-tdx.rootfs-20241107200854.wic.vhd",
//           "attestation_type": "azure-tdx",
//           "measurements": {
//               "4": {
//                   "expected": "1b8cd655f5ebdf50bedabfb5db6b896a0a7c56de54f318103a2de1e7cea57b6b"
//               },
//               ...
//           }
//       },
//       ...
//   ]
//
// Data schema v1:
//
//   {
//       "azure-tdx-example": {
//           "15": {
//               "expected": "0000000000000000000000000000000000000000000000000000000000000000"
//           },
//   		...
//       },
//       "dcap-tdx-example": {
//           "4": {
//               "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//           },
//   		...
//       }
//   }
//
// The v2 data schema is an improvement because it allows additional data fields
// besides the raw measurements.
//

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

// ExpectedMeasurements is a struct that represents a list of expected measurements,
// and allows checking if given measurements matches a known one.
type ExpectedMeasurements struct {
	Measurements []MeasurementsContainer
}

type MeasurementEntry struct {
	Expected string `json:"expected"`
}

type MeasurementsContainer struct {
	MeasurementID   string                      `json:"measurement_id"`
	AttestationType string                      `json:"attestation_type"`
	Measurements    map[string]MeasurementEntry `json:"measurements"`
}

type LegacyMeasurementsContainer map[string]map[string]MeasurementEntry

// NewExpectedMeasurementsFromFile returns an ExpectedMeasurements instance,
// with the measurements loaded from a file or URL.
func NewExpectedMeasurementsFromFile(path string) (m *ExpectedMeasurements, err error) {
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

	m = &ExpectedMeasurements{}

	// Try to load v2 data schema
	err = json.Unmarshal(data, &m.Measurements)
	// If loading v2 format fails, try to load the legacy v1 data schema
	if err != nil {
		var legacyData LegacyMeasurementsContainer
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
func (m *ExpectedMeasurements) Contains(measurements map[string]string) (found bool, measurementID string) {
	// For every known container, all known measurements match (and additional ones are ignored)
	for _, container := range m.Measurements {
		allMatch := true
		for key, value := range container.Measurements {
			if value.Expected != measurements[key] {
				allMatch = false
				break
			}
		}

		if allMatch {
			return true, container.MeasurementID
		}
	}

	return false, ""
}
