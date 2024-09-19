package proxy

import (
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
	p.proxy.ServeHTTP(w, r)
}
