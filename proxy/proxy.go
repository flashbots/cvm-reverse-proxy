package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type Proxy struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
}

func NewProxy(targetUrl string) *Proxy {
	target, err := url.Parse(targetUrl)
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	return &Proxy{target: target, proxy: proxy}
}

func (p *Proxy) WithTransport(transport *http.Transport) *Proxy {
	p.proxy.Transport = transport
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Host = p.target.Host

	if r.Header.Get("X-Forwarded-For") != "" {
		http.Error(w, "unexpected X-Forwarded-For header passed", http.StatusForbidden)
		return
	}

	r.Header.Set("X-Forwarded-For", r.RemoteAddr) // Note: not very reliable. Maybe we should set and check X-Real-IP. Also, X-Forwarded-For might have already been set.

	for headerKey := range r.Header {
		if strings.HasPrefix("x-flashbots-cert-extensions", strings.ToLower(headerKey)) {
			http.Error(w, "unexpected X-Flashbots-Cert-Extensions header passed", http.StatusForbidden)
			return
		}
	}

	for _, cert := range r.TLS.PeerCertificates {
		for _, ext := range cert.Extensions {
			atlsVariant, err := ExtractExtensionATLSVariant(&ext)
			if err != nil {
				// not an ATLS variant, simply skip
				continue
			}

			measurements, err := ExtractMeasurementsFromExtension(&ext, atlsVariant)
			if err != nil {
				http.Error(w, "could not extract measurement from tls extension", http.StatusTeapot)
				return
			}

			marshaledPcrs, err := json.Marshal(measurements)
			if err != nil {
				http.Error(w, "could not marshal measurement extracted from tls extension", http.StatusInternalServerError)
				return
			}

			r.Header.Set("X-Flashbots-Cert-Extensions-"+ext.Id.String(), string(marshaledPcrs))
		}
	}

	p.proxy.ServeHTTP(w, r)
}
