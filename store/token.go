// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package store

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/errgo.v1"
)

// TokenStore implements the read and write actions in order to handle
// token information.
type TokenStore string

// Get retrieves the token stored for the given URL, if present.
func (s TokenStore) Get(url string) ([]byte, error) {
	path := filepath.Join(string(s), filenameForURL(url))
	b, err := ioutil.ReadFile(path)
	if err != nil && os.IsNotExist(err) {
		err = nil
	}
	return b, errgo.Mask(err)
}

// Set stores the given token for the given URL.
func (s TokenStore) Set(url string, token []byte) error {
	path := filepath.Join(string(s), filenameForURL(url))
	if len(token) == 0 {
		err := os.Remove(path)
		if err != nil && os.IsNotExist(err) {
			err = nil
		}
		return errgo.Mask(err)
	}
	if err := os.MkdirAll(string(s), 0700); err != nil {
		return errgo.Mask(err)
	}
	return errgo.Mask(ioutil.WriteFile(path, token, 0600))
}

func filenameForURL(url string) string {
	sb := new(strings.Builder)
	sb.Grow(len(url))
	for _, c := range url {
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '.' || c == '_' || c == '-' {
			sb.WriteByte(byte(c))
		} else {
			// Theoretically this could cause a clash, but it is unlikely to
			// do so on any real servers. These are always likely to have
			// unique host names, which will not be masked by this transform.
			sb.WriteByte('-')
		}
	}
	return sb.String()
}
