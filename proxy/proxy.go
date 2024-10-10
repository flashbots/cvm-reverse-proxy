package proxy

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	"github.com/flashbots/cvm-reverse-proxy/internal/attestation/variant"
)

type Proxy struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
	log    *slog.Logger

	validatorOIDs []asn1.ObjectIdentifier
}

const (
	AttestationTypeHeader string = "X-Flashbots-Attestation-Type"
	MeasurementHeader     string = "X-Flashbots-Measurement"
)

func NewProxy(log *slog.Logger, targetURL string, validators []atls.Validator) *Proxy {
	target, err := url.Parse(targetURL)
	if err != nil {
		panic(err)
	}

	httpproxy := httputil.NewSingleHostReverseProxy(target)

	var validatorOIDs []asn1.ObjectIdentifier
	for _, validator := range validators {
		validatorOIDs = append(validatorOIDs, validator.OID())
	}

	proxy := &Proxy{
		log:           log,
		target:        target,
		proxy:         httpproxy,
		validatorOIDs: validatorOIDs,
	}

	// Forwards validated measurement to the *client*
	httpproxy.ModifyResponse = func(res *http.Response) error {
		if res.Header.Get(MeasurementHeader) != "" {
			return errors.New("unexpected measurement header passed")
		}
		if res.Header.Get(AttestationTypeHeader) != "" {
			return errors.New("unexpected attestation type header passed")
		}

		if res.TLS != nil {
			_, err := proxy.copyMeasurementsToHeader(res.TLS, &res.Header)
			return err
		}

		return nil
	}

	return proxy
}

func (p *Proxy) WithTransport(transport *http.Transport) *Proxy {
	p.proxy.Transport = transport
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Host = p.target.Host

	p.log.Debug("[proxy-request] request received")

	// Note: the reverse proxy adds X-Forwarded-For header!
	if r.Header.Get(MeasurementHeader) != "" {
		http.Error(w, "unexpected measurement header passed", http.StatusForbidden)
	}
	if r.Header.Get(AttestationTypeHeader) != "" {
		http.Error(w, "unexpected attestation type header passed", http.StatusForbidden)
	}

	if r.TLS != nil {
		p.log.Debug("[proxy-request] adding measurement headers")

		// Forwards validated measurement to the *proxied-to service*
		errStatus, err := p.copyMeasurementsToHeader(r.TLS, &r.Header)
		if err != nil {
			http.Error(w, err.Error(), errStatus)
			return
		}
	}

	p.log.Debug("[proxy-request] forwarding to target")
	timeStarted := time.Now()

	p.proxy.ServeHTTP(w, r)

	duration := time.Since(timeStarted).String()
	p.log.With("duration", duration).Info("[proxy-request] proxying complete")
}

func (p *Proxy) getMeasurementsFromTLS(conn *tls.ConnectionState) (atlsVariant variant.Variant, measurements map[uint32][]byte, err error) {
	// In verifyEmbeddedReport which is used to validate the extensions, only the first matching extension is validated! Refuse to accept multiple
	var ATLSExtension *pkix.Extension = nil
	for _, cert := range conn.PeerCertificates {
		for _, ext := range cert.Extensions {
			for _, validatorOID := range p.validatorOIDs {
				if ext.Id.Equal(validatorOID) {
					if ATLSExtension != nil {
						return nil, nil, errors.New("more than one ATLS extension provided, refusing to continue")
					}
					ATLSExtension = &ext
				}
			}
		}
	}

	if ATLSExtension == nil {
		return nil, nil, nil
	}

	atlsVariant, err = variant.FromOID(ATLSExtension.Id)
	if err != nil {
		return nil, nil, errors.New("could not get ATLS variant back from a matched extension")
	}

	measurements, err = ExtractMeasurementsFromExtension(ATLSExtension, atlsVariant)
	if err != nil {
		return nil, nil, errors.New("could not extract measurement from tls extension")
	}

	return atlsVariant, measurements, nil
}

func (p *Proxy) copyMeasurementsToHeader(conn *tls.ConnectionState, header *http.Header) (int, error) {
	atlsVariant, extractedMeasurements, err := p.getMeasurementsFromTLS(conn)
	if err != nil {
		return http.StatusTeapot, err
	} else if extractedMeasurements == nil {
		p.log.Debug("[proxy-request: add-headers] no measurements, not adding headers")
		return 0, nil
	}

	measurementsInHeaderFormat := make(map[string]string, len(extractedMeasurements))
	for pcr, value := range extractedMeasurements {
		measurementsInHeaderFormat[string(pcr)] = hex.EncodeToString(value)
	}

	marshaledPcrs, err := json.Marshal(measurementsInHeaderFormat)
	if err != nil {
		return http.StatusInternalServerError, errors.New("could not marshal measurement extracted from tls extension")
	}

	header.Set(AttestationTypeHeader, atlsVariant.String())
	header.Set(MeasurementHeader, string(marshaledPcrs))

	p.log.With(AttestationTypeHeader, atlsVariant.String()).With(MeasurementHeader, string(marshaledPcrs)).Debug("[proxy-request: add-headers] meaasurement headers added")
	return 0, nil
}
