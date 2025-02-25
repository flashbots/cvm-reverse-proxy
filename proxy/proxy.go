package proxy

import (
	"crypto/x509"
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

const (
	AttestationTypeHeader        string = "X-Flashbots-Attestation-Type"
	MeasurementHeader            string = "X-Flashbots-Measurement"
	ProxyTargetURLHeader         string = "X-Flashbots-Proxy-Target-URL"
	ProxyTargetMeasurementHeader string = "X-Flashbots-Proxy-Target-Measurement"
)

type Proxy struct {
	proxyHandler http.HandlerFunc
	log          *slog.Logger

	validatorOIDs []asn1.ObjectIdentifier
}

func NewProxy(log *slog.Logger, proxyHandler http.HandlerFunc, validators []atls.Validator) *Proxy {
	var validatorOIDs []asn1.ObjectIdentifier
	for _, validator := range validators {
		validatorOIDs = append(validatorOIDs, validator.OID())
	}

	proxy := &Proxy{
		log:           log,
		proxyHandler:  proxyHandler,
		validatorOIDs: validatorOIDs,
	}

	return proxy
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.log.Debug("[proxy-request] request received")

	// Note: the reverse proxy adds X-Forwarded-For header!
	if r.Header.Get(MeasurementHeader) != "" {
		http.Error(w, "unexpected measurement header passed", http.StatusForbidden)
		return
	}
	if r.Header.Get(AttestationTypeHeader) != "" {
		http.Error(w, "unexpected attestation type header passed", http.StatusForbidden)
		return
	}

	if r.TLS != nil {
		p.log.Debug("[proxy-request] adding measurement headers")

		// Forwards validated measurement to the *proxied-to service*
		errStatus, err := copyMeasurementsToHeader(p.log, r.TLS.PeerCertificates, &r.Header, p.validatorOIDs)
		if err != nil {
			http.Error(w, err.Error(), errStatus)
			return
		}
	}

	p.log.Debug("[proxy-request] forwarding to target")
	timeStarted := time.Now()

	p.proxyHandler(w, r)

	duration := time.Since(timeStarted).String()
	p.log.With("duration", duration).Info("[proxy-request] proxying complete")
}

type MultiServiceMiddleware struct {
	Handlers map[ServiceTag]http.HandlerFunc
}

func NewMultiServiceMiddleware(handlers map[ServiceTag]http.HandlerFunc) *MultiServiceMiddleware {
	return &MultiServiceMiddleware{Handlers: handlers}
}

func (mp *MultiServiceMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	measurement := r.Header.Get(ProxyTargetMeasurementHeader)
	if measurement == "" {
		http.Error(w, "proxy target measurement header not set", http.StatusBadRequest)
		return
	}
	r.Header.Del(ProxyTargetMeasurementHeader)

	// Assume measurement is the service tag (could also be an id, or a raw measurement)
	handler, found := mp.Handlers[ServiceTag(measurement)]
	if !found {
		http.Error(w, "unknown proxy target measurement", http.StatusBadRequest)
		return
	}

	handler(w, r)
}

func NewSingleHostReverseProxyFromUrl(log *slog.Logger, validators []atls.Validator, targetURL string) *httputil.ReverseProxy {
	target, err := url.Parse(targetURL)
	if err != nil {
		panic(err)
	}

	rproxy := httputil.NewSingleHostReverseProxy(target)

	defaultDirector := rproxy.Director
	rproxy.Director = func(r *http.Request) {
		defaultDirector(r)
		r.Host = target.Host
	}

	var validatorOIDs []asn1.ObjectIdentifier
	for _, validator := range validators {
		validatorOIDs = append(validatorOIDs, validator.OID())
	}

	rproxy.ModifyResponse = func(r *http.Response) error { return forwardMeasurementsToClient(log, r, validatorOIDs) }

	return rproxy
}

func NewDynamicHostReverseProxyFromHeader(log *slog.Logger, validators []atls.Validator, rproxyFactory func(*url.URL) *httputil.ReverseProxy) http.HandlerFunc {
	var validatorOIDs []asn1.ObjectIdentifier
	for _, validator := range validators {
		validatorOIDs = append(validatorOIDs, validator.OID())
	}

	modifyResponse := func(r *http.Response) error { return forwardMeasurementsToClient(log, r, validatorOIDs) }

	return func(w http.ResponseWriter, r *http.Request) {
		targetHeader := r.Header.Get(ProxyTargetURLHeader)
		if targetHeader == "" {
			http.Error(w, "proxy target header not set", http.StatusBadRequest)
			return
		}
		r.Header.Del(ProxyTargetURLHeader)

		targetURL, err := url.Parse(targetHeader)
		if err != nil {
			// TODO: log err
			http.Error(w, "proxy target header not a valid url", http.StatusBadRequest)
			return
		}

		rproxy := rproxyFactory(targetURL)

		defaultDirector := rproxy.Director
		rproxy.Director = func(r *http.Request) {
			defaultDirector(r)
			r.Host = targetURL.Host
		}

		rproxy.ModifyResponse = modifyResponse
		rproxy.ServeHTTP(w, r)
	}
}

func GetMeasurementsFromTLS(certs []*x509.Certificate, validatorOIDs []asn1.ObjectIdentifier) (atlsVariant variant.Variant, measurements map[uint32][]byte, err error) {
	// In verifyEmbeddedReport which is used to validate the extensions, only the first matching extension is validated! Refuse to accept multiple
	var ATLSExtension *pkix.Extension = nil
	for _, cert := range certs {
		for _, ext := range cert.Extensions {
			for _, validatorOID := range validatorOIDs {
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

func copyMeasurementsToHeader(log *slog.Logger, certs []*x509.Certificate, header *http.Header, validatorOIDs []asn1.ObjectIdentifier) (int, error) {
	atlsVariant, extractedMeasurements, err := GetMeasurementsFromTLS(certs, validatorOIDs)
	if err != nil {
		return http.StatusTeapot, err
	} else if extractedMeasurements == nil {
		log.Debug("[proxy-request: add-headers] no measurements, not adding headers")
		return 0, nil
	}

	measurementsInHeaderFormat := make(map[uint32]string, len(extractedMeasurements))
	for pcr, value := range extractedMeasurements {
		measurementsInHeaderFormat[pcr] = hex.EncodeToString(value)
	}

	marshaledPcrs, err := json.Marshal(measurementsInHeaderFormat)
	if err != nil {
		return http.StatusInternalServerError, errors.New("could not marshal measurement extracted from tls extension")
	}

	header.Set(AttestationTypeHeader, atlsVariant.String())
	header.Set(MeasurementHeader, string(marshaledPcrs))

	log.With(AttestationTypeHeader, atlsVariant.String()).With(MeasurementHeader, string(marshaledPcrs)).Debug("[proxy-request: add-headers] measurement headers added")
	return 0, nil
}

// Forwards validated measurement to the *client*
func forwardMeasurementsToClient(log *slog.Logger, res *http.Response, validatorOIDs []asn1.ObjectIdentifier) error {
	if res.Header.Get(MeasurementHeader) != "" {
		return errors.New("unexpected measurement header passed")
	}
	if res.Header.Get(AttestationTypeHeader) != "" {
		return errors.New("unexpected attestation type header passed")
	}

	if res.TLS != nil {
		_, err := copyMeasurementsToHeader(log, res.TLS.PeerCertificates, &res.Header, validatorOIDs)
		return err
	}

	return nil
}
