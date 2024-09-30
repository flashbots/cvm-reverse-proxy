package proxy

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	log.Println(r.URL)
	r.Host = p.target.Host
	r.Header.Set("X-Forwarded-For", r.RemoteAddr) // Note: not very reliable. Maybe we should set and check X-Real-IP. Also, X-Forwarded-For might have already been set.

	for _, cert := range r.TLS.PeerCertificates {
		for _, ext := range cert.Extensions {
			atlsVariant, err := ExtractExtensionATLSVariant(&ext)
			if err != nil {
				// not an ATLS variant, simply skip
				continue
			}

			measurements, err := ExtractMeasurementsFromExtension(&ext, atlsVariant)
			if err != nil {
				// TODO: log this error!
				continue // TODO: should we just terminate with 400?
			}

			marshaledPcrs, err := json.Marshal(measurements)
			if err != nil {
				// TODO: log this error!
				continue // TODO: should we just terminate with 400?
			}

			r.Header.Set("X-Flashbots-Cert-Extensions-"+ext.Id.String(), string(marshaledPcrs))
		}
	}

	p.proxy.ServeHTTP(w, r)
}
