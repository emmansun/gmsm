//go:build js && wasm
// +build js,wasm

package smx509

// Possible certificate files; stop after finding one.
var certFiles = []string{}

// Possible directories with certificate files; all will be read.
var certDirectories = []string{}
