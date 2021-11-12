// +build js,wasm

package main

import (
	"github.com/gonyyi/go-aes256cbc"
	"syscall/js"
)

func Enc() js.Func{
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "Invalid no of arguments passed)"
		}

		out, err := aes256cbc.Base64Encrypt([]byte(args[0].String()), []byte(args[1].String()), nil)
		if err!=nil {
			return err.Error()
		}

		return string(out)
	})
}

func Dec() js.Func{
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "Invalid no of arguments passed)"
		}

		out, err := aes256cbc.Base64Decrypt([]byte(args[0].String()), []byte(args[1].String()))
		// println("Args[0]: ["+args[0].String()+"]", len(args[0].String()))
		// println("Args[1]: ["+args[1].String()+"]", len(args[1].String()))
		if err!=nil {
			return err.Error()
		}

		return string(out)
	})
}


func main() {
	println("GO-AES256CBC v0.1.1\nCopyright 2021 Gon Y. Yi <https://gonyyi.com/copyright>\ngonEnc(data, key), gonDec(data,key)\n")
	js.Global().Set("gonEnc", Enc())
	js.Global().Set("gonDec", Dec())
	<-make(chan bool) // keep running when loaded by a browser
}

