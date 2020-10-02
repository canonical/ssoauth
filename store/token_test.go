// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package store_test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/ssoauth/store"
)

func TestGetWhenFileExists(t *testing.T) {
	c := qt.New(t)
	storeLocation := c.Mkdir()
	tempFile, err := ioutil.TempFile(storeLocation, "")
	c.Assert(err, qt.IsNil)

	token := []byte("popeye")
	url := tempFile.Name()
	fileName := filepath.Base(url)
	err = ioutil.WriteFile(url, token, 0644)
	c.Assert(err, qt.IsNil)

	ts := store.TokenStore(storeLocation)
	bytes, err := ts.Get(fileName)
	c.Assert(err, qt.IsNil)
	c.Assert(token, qt.DeepEquals, bytes)
}

func TestGetWhenDoesNotExistIsOK(t *testing.T) {
	c := qt.New(t)
	storeLocation := "/does-not/exist/yyy/zzz"

	ts := store.TokenStore(storeLocation)
	_, err := ts.Get("abc")
	c.Assert(err, qt.IsNil)
}

func TestSetWhenDoesNotExistIsOK(t *testing.T) {
	c := qt.New(t)
	storeLocation := "/etc/passwd/"

	ts := store.TokenStore(storeLocation)
	err := ts.Set("foo", []byte{})
	c.Assert(err, qt.ErrorMatches, `remove /etc/passwd/foo: not a directory`)
}
