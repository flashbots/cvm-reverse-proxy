package tdx

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/flashbots/cvm-reverse-proxy/internal/attestation"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
)

// RemoteQuoteProviderConfig holds configuration for the remote TDX quote provider
type RemoteQuoteProviderConfig struct {
	// BaseURL is the base URL of the remote TDX quote provider service
	BaseURL string

	// HTTPClient is the HTTP client used to communicate with the remote service
	HTTPClient *http.Client

	// Timeout is the maximum duration to wait for a response from the remote service
	Timeout time.Duration
}

// DefaultRemoteQuoteProviderConfig returns a default configuration for the remote TDX quote provider
func DefaultRemoteQuoteProviderConfig(url string) *RemoteQuoteProviderConfig {
	return &RemoteQuoteProviderConfig{
		BaseURL: url,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}

// RemoteIssuer is a TDX attestation issuer that uses a remote quote provider service
type RemoteIssuer struct {
	variant.QEMUTDX

	config *RemoteQuoteProviderConfig
	log    attestation.Logger
}

// NewRemoteIssuer initializes a new TDX Issuer that uses a remote quote provider
func NewRemoteIssuer(config *RemoteQuoteProviderConfig, log attestation.Logger) *RemoteIssuer {
	if log == nil {
		log = attestation.NOPLogger{}
	}

	return &RemoteIssuer{
		config: config,
		log:    log,
	}
}

// Issue issues a TDX attestation document using the remote quote provider
func (i *RemoteIssuer) Issue(ctx context.Context, userData []byte, nonce []byte) (attDoc []byte, err error) {
	i.log.Info("Issuing attestation statement using remote quote provider")
	defer func() {
		if err != nil {
			i.log.Warn(fmt.Sprintf("Failed to issue attestation document: %s", err))
		}
	}()

	// Create extra data from user data and nonce
	extraData := attestation.MakeExtraData(userData, nonce)

	// Convert extra data to hex for URL path
	extraDataHex := hex.EncodeToString(extraData)

	// Prepare the request URL
	url := fmt.Sprintf("%s/attest/%s", i.config.BaseURL, extraDataHex)

	// Create a new request with a context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}

	// Execute the request
	resp, err := i.config.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling remote quote provider: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote quote provider returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read the quote
	rawQuote, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading quote from response: %w", err)
	}

	// Wrap the quote in our attestation document format
	rawAttDoc, err := encodeAttestationDocument(rawQuote, userData)
	if err != nil {
		return nil, fmt.Errorf("marshaling attestation document: %w", err)
	}

	i.log.Info(fmt.Sprintf("Successfully issued attestation document with remote quote provider, size: %d bytes", len(rawAttDoc)))
	return rawAttDoc, nil
}

// encodeAttestationDocument encodes a TDX attestation document with the given quote and user data
func encodeAttestationDocument(rawQuote []byte, userData []byte) ([]byte, error) {
	attDoc := tdxAttestationDocument{
		RawQuote: rawQuote,
		UserData: userData,
	}
	return json.Marshal(attDoc)
}
