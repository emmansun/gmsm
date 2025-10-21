// Copyright 2021 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le || s390x || loong64)

package sm3

func block(dig *digest, p []byte) {
	blockGeneric(dig, p)
}
