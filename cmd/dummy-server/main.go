package main

import (
	"io"
	"net/http"
)

func getRoot(w http.ResponseWriter, r *http.Request) {
	_, _ = io.WriteString(w, "checkcheck\n")
}

func main() {
	http.HandleFunc("/", getRoot)
	_ = http.ListenAndServe(":8085", nil)
}
