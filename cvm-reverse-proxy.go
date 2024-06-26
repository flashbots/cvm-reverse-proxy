package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/konvera/geth-sev/constellation/atls"
	"github.com/konvera/geth-sev/constellation/attestation/azure/tdx"
	"github.com/konvera/geth-sev/constellation/config"
)

type Proxy struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	r.Host = p.target.Host
	p.proxy.ServeHTTP(w, r)
}

type attestationLogger struct {
}

func (w attestationLogger) Info(format string, args ...any) {
	log.Print(fmt.Sprintf(format, args...))
}

func (w attestationLogger) Warn(format string, args ...any) {
	log.Print(fmt.Sprintf(format, args...))
}

func main() {
	// Define flags for each parameter
	client := flag.Bool("client", false, "Set to true if running as a client")
	server := flag.Bool("server", false, "Set to true if running as a server")
	targetPort := flag.Int("target-port", 0, "Target port number")
	targetDomain := flag.String("target-domain", "https://localhost", "Target domain")
	listenPort := flag.Int("listen-port", 0, "Listen port number")
	measurements := flag.String("measurements", "", "Path to JSON Attestation Measurement file")

	// Parse the command-line flags
	flag.Parse()

	// Validate that either client or server is true, but not both
	if *client && *server {
		log.Fatal("Error: Both client and server cannot be true simultaneously.")
	}

	proxyTarget := *targetDomain + ":" + strconv.Itoa(*targetPort) + "/"
	if *client {
		client_side_tls_termination(proxyTarget, strconv.Itoa(*listenPort), *measurements)
	}

	if *server {
		server_side_tls_termination(proxyTarget, strconv.Itoa(*listenPort))
	}
}

func client_side_tls_termination(targetUrl string, listenPort string, measurementsPath string) {

	// Read the measurements file
	jsonMeasurements, err := ioutil.ReadFile(measurementsPath)
	if err != nil {
		log.Fatal("Error reading file:", err)
	}

	attConfig := config.DefaultForAzureTDX()
	err = json.Unmarshal(jsonMeasurements, &attConfig.Measurements)
	if err != nil {
		log.Fatal("Error decoding measurements:", err)
	}

	validators := []atls.Validator{tdx.NewValidator(attConfig, attestationLogger{})}
	tlsConfig, err := atls.CreateAttestationClientTLSConfig(nil, validators)
	if err != nil {
		log.Fatal("Error creating ATLS config:", err)
	}

	// Replace 'target' with the URL of the server you want to proxy to
	target, err := url.Parse(targetUrl)
	if err != nil {
		panic(err)
	}

	// Create a new ReverseProxy instance
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{TLSClientConfig: tlsConfig}

	// Create a new Proxy instance
	p := &Proxy{target: target, proxy: proxy}

	// Start the HTTP server and register the Proxy instance as the handler
	log.Printf("About to listen on :" + listenPort + ". Go to http://127.0.0.1:" + listenPort + "/")
	err = http.ListenAndServe(":"+listenPort, p)
	if err != nil {
		panic(err)
	}
}

func server_side_tls_termination(proxyTarget string, listenPort string) {
	target, err := url.Parse(proxyTarget)
	if err != nil {
		panic(err)
	}

	// Create a new ReverseProxy instance
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Create a new Proxy instance
	p := &Proxy{target: target, proxy: proxy}

	// Create attested TLS config
	issuer := tdx.NewIssuer(nil)
	confTLS, err := atls.CreateAttestationServerTLSConfig(issuer, nil)
	if err != nil {
		panic(err)
	}

	// Create an HTTP server
	server := &http.Server{
		Addr:      ":" + listenPort,
		Handler:   p,
		TLSConfig: confTLS,
	}

	// Create a TLS listener
	tlsListener, err := tls.Listen("tcp", server.Addr, confTLS)
	if err != nil {
		log.Fatal("Error creating TLS listener: ", err)
	}

	log.Printf("About to listen on :" + listenPort + ". Go to https://127.0.0.1:" + listenPort + "/")
	err = server.Serve(tlsListener)
	if err != nil {
		log.Fatal("Error serving: ", err)
	}
}
