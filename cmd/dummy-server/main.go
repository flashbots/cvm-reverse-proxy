package main

import (
	"io"
	"log"
	"net/http"
)

func getRoot(w http.ResponseWriter, r *http.Request) {
	// Print all headers
	log.Println("Received request with headers:")
	for name, values := range r.Header {
		for _, value := range values {
			log.Printf("  %s: %s", name, value)
		}
	}

	_, _ = io.WriteString(w, "checkcheck\n")
}

func main() {
	listenAddr := ":8085"
	http.HandleFunc("/", getRoot)

	log.Printf("Starting dummy server on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
