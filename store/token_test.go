// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package store_test

import (
	"context"
	"io/ioutil"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/ssoauth/store"
)

func TestDirTokenStoreRoundTrip(t *testing.T) {
	c := qt.New(t)
	ts := store.DirTokenStore(c.Mkdir())
	err := ts.Set(context.Background(), "https://example.com", []byte("test-token"))
	c.Assert(err, qt.IsNil)
	token, err := ts.Get(context.Background(), "https://example.com")
	c.Assert(err, qt.IsNil)
	c.Assert(string(token), qt.Equals, "test-token")
}

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

	ts := store.DirTokenStore(storeLocation)
	bytes, err := ts.Get(context.Background(), fileName)
	c.Assert(err, qt.IsNil)
	c.Assert(token, qt.DeepEquals, bytes)
}

func TestGetWhenDoesNotExistIsOK(t *testing.T) {
	c := qt.New(t)
	storeLocation := "/does-not/exist/yyy/zzz"

	ts := store.DirTokenStore(storeLocation)
	_, err := ts.Get(context.Background(), "abc")
	c.Assert(err, qt.IsNil)
}

func TestSetWhenDoesNotExistIsOK(t *testing.T) {
	c := qt.New(t)
	storeLocation := "/etc/passwd/"

	ts := store.DirTokenStore(storeLocation)
	err := ts.Set(context.Background(), "foo", []byte{})
	c.Assert(err, qt.ErrorMatches, `remove /etc/passwd/foo: not a directory`)
}
