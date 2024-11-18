package common

//
// Helper to load expected measurements from a file or URL, and compare
// provided measurements against them.
//
// Compatible with measurements data schema v2 (see measurements.json)
// as well as the legacy v1 schema.
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

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/measurements"
)

// ExpectedMeasurements is a struct that represents a list of expected measurements,
// and allows checking if given measurements matches a known one.
type ExpectedMeasurements struct {
	Measurements []MeasurementsContainer
}

type MeasurementsContainer struct {
	MeasurementID   string         `json:"measurement_id"`
	AttestationType string         `json:"attestation_type"`
	Measurements    measurements.M `json:"measurements"`
}

type LegacyMeasurementsContainer map[string]measurements.M

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

	// Try to load the v2 data schema, if that fails fall back to legacy v1 schema
	if err = json.Unmarshal(data, &m.Measurements); err != nil {
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
func (m *ExpectedMeasurements) Contains(measurements map[uint32][]byte) (found bool, foundMeasurement *MeasurementsContainer) {
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
