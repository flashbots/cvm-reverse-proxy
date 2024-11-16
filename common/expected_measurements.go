package common

//
// Helper to load expected measurements (from a file or URL),
// and compare provided measurements against them.
//
// Expected measurements format: https://measurements.builder.flashbots.net
//

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

// ExpectedMeasurements is a struct that represents a list of expected measurements.
// It can also take a list of measurements and see if it matches a known one.
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

	m = &ExpectedMeasurements{
		Measurements: make([]MeasurementsContainer, 0),
	}
	err = json.Unmarshal(data, &m.Measurements)
	return m, err
}

// Contains checks if the provided measurements match one of the known measurements. Any keys in the provided
// measurements which are not in the known measurements are ignored.
func (m *ExpectedMeasurements) Contains(measurements map[string]string) (bool, string) {
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
