package store

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestGetWhenFileExists(t *testing.T) {
	c := qt.New(t)
	storeLocation := os.TempDir()
	tempFile, err := ioutil.TempFile(storeLocation, "")
	c.Assert(err, qt.IsNil)
	defer os.Remove(tempFile.Name())

	token := []byte("popeye")
	url := tempFile.Name()
	fileName := filepath.Base(url)
	err = ioutil.WriteFile(url, token, 0644)
	c.Assert(err, qt.IsNil)

	store := TokenStore(storeLocation)
	bytes, err := store.Get(fileName)
	c.Assert(err, qt.IsNil)
	c.Assert(token, qt.DeepEquals, bytes)
}

func TestGetWhenDoesNotExistIsOK(t *testing.T) {
	c := qt.New(t)
	storeLocation := "/does-not/exist/yyy/zzz"

	store := TokenStore(storeLocation)
	_, err := store.Get("abc")
	c.Assert(err, qt.IsNil)
}

func TestSetWhenDoesNotExistIsKO(t *testing.T) {
	c := qt.New(t)
	storeLocation := "/etc/passwd/"

	store := TokenStore(storeLocation)
	err := store.Set("foo", []byte{})
	c.Assert(err, qt.ErrorMatches, `remove /etc/passwd/foo: not a directory`)
}
