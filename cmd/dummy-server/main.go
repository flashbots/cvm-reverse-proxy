package main

import (
	"io"
	"net/http"
)

func getRoot(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "checkcheck\n")
}

func main() {
	http.HandleFunc("/", getRoot)
	http.ListenAndServe(":8085", nil)
}
