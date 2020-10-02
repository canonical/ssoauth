// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package store

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/errgo.v1"
)

// DirTokenStore provides filesystem storage for arbitrary tokens, keyed by
// URL. The value of the DirTokenStore is the directory in which the tokens
// are stored, if this directory does not exist it will be created when
// required.
type DirTokenStore string

// Get retrieves the token stored for the given URL, if present.
func (s DirTokenStore) Get(_ context.Context, url string) ([]byte, error) {
	path := filepath.Join(string(s), filenameForURL(url))
	b, err := ioutil.ReadFile(path)
	if err != nil && os.IsNotExist(err) {
		err = nil
	}
	return b, errgo.Mask(err)
}

// Set stores the given token for the given URL.
func (s DirTokenStore) Set(_ context.Context, url string, token []byte) error {
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
