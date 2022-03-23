#!/usr/bin/env sh

GOOS=js GOARCH=wasm go build -o ./server/gon_enc.wasm

