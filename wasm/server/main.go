package main

import (
	_ "embed"
	"net/http"
)

//go:embed index.html
var indexHtml []byte
//go:embed wasm_exec.js
var wasmJS []byte
//go:embed gon_enc.wasm
var wasmGo []byte

func js() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(wasmJS)
	}
}
func wasm() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(wasmGo)
	}
}
func index() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(indexHtml)
	}
}

func main() {
	http.HandleFunc("/wasm_exec.js", js())
	http.HandleFunc("/gon_enc.wasm", wasm())
	http.HandleFunc("/", index())
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		println(err.Error())
		return
	}
}
