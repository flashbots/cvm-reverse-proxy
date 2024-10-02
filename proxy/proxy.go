package proxy

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"cvm-reverse-proxy/internal/atls"
	"cvm-reverse-proxy/internal/attestation/variant"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type Proxy struct {
	target *url.URL
	proxy  *httputil.ReverseProxy

	validatorOIDs []asn1.ObjectIdentifier
}

func NewProxy(targetUrl string, validators []atls.Validator) *Proxy {
	target, err := url.Parse(targetUrl)
	if err != nil {
		panic(err)
	}

	httpproxy := httputil.NewSingleHostReverseProxy(target)

	var validatorOIDs []asn1.ObjectIdentifier
	for _, validator := range validators {
		validatorOIDs = append(validatorOIDs, validator.OID())
	}

	proxy := &Proxy{target: target, proxy: httpproxy, validatorOIDs: validatorOIDs}

	// Forwards validated measurement to the *client*
	httpproxy.ModifyResponse = func(res *http.Response) error {
		for headerKey := range res.Header {
			if strings.HasPrefix("x-flashbots-cert-extensions", strings.ToLower(headerKey)) {
				return errors.New("unexpected X-Flashbots-Cert-Extensions header passed")
			}
		}

		if res.TLS != nil {
			err, _ := proxy.copyMeasurementsToHeader(res.TLS, &res.Header)
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

	// Note: the reverse proxy adds X-Forwarded-For header!

	for headerKey := range r.Header {
		if strings.HasPrefix("x-flashbots-cert-extensions", strings.ToLower(headerKey)) {
			http.Error(w, "unexpected X-Flashbots-Cert-Extensions header passed", http.StatusForbidden)
			return
		}
	}

	if r.TLS != nil {
		// Forwards validated measurement to the *proxied-to service*
		err, errStatus := p.copyMeasurementsToHeader(r.TLS, &r.Header)
		if err != nil {
			http.Error(w, err.Error(), errStatus)
			return
		}
	}

	p.proxy.ServeHTTP(w, r)
}

func (p *Proxy) copyMeasurementsToHeader(conn *tls.ConnectionState, header *http.Header) (error, int) {
	// In verifyEmbeddedReport which is used to validate the extensions, only the first matching extension is validated! Refuse to accept multiple
	var ATLSExtension *pkix.Extension = nil
	for _, cert := range conn.PeerCertificates {
		for _, ext := range cert.Extensions {
			for _, validatorOID := range p.validatorOIDs {
				if ext.Id.Equal(validatorOID) {
					if ATLSExtension != nil {
						return errors.New("more than one ATLS extension provided, refusing to continue"), http.StatusBadRequest
					}
					ATLSExtension = &ext
				}
			}
		}
	}

	if ATLSExtension == nil {
		return nil, 0
	}

	atlsVariant, err := variant.FromOID(ATLSExtension.Id)
	if err != nil {
		return errors.New("could not get ATLS variant back from a matched extension"), http.StatusTeapot
	}

	measurements, err := ExtractMeasurementsFromExtension(ATLSExtension, atlsVariant)
	if err != nil {
		return errors.New("could not extract measurement from tls extension"), http.StatusTeapot
	}

	marshaledPcrs, err := json.Marshal(measurements)
	if err != nil {
		return errors.New("could not marshal measurement extracted from tls extension"), http.StatusInternalServerError
	}

	header.Set("X-Flashbots-Cert-Extensions-"+ATLSExtension.Id.String(), string(marshaledPcrs))
	return nil, 0
}
