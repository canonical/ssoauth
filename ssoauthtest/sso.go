// Package ssoauthtest contains test helpers for SSO authentication.
package ssoauthtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	errgo "gopkg.in/errgo.v1"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/canonical/ssoauth"
)

const (
	TimeFormat = "2006-01-02T15:04:05.000000"

	defaultLocation = "login.example.com"
	keyBits         = 2048
)

type Discharger struct {
	mu  sync.Mutex
	key *rsa.PrivateKey
}

// Get the location of this discharger.
func (d *Discharger) Location() string {
	return defaultLocation
}

// Get the public key for this discharger. The key is generated the first
// time it is requested.
func (d *Discharger) PublicKey() *rsa.PublicKey {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.key == nil {
		var err error
		d.key, err = rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			panic(err)
		}
	}
	return d.key.Public().(*rsa.PublicKey)
}

// Discharge creates a discharge macaroon for the given caveatID. If acc,
// expires or validSince are non-zero then matching caveats will be added
// to the discharge macaroon to represent the given values.
func (d *Discharger) Discharge(caveatID []byte, acc *ssoauth.Account, expires, validSince time.Time) (*macaroon.Macaroon, error) {
	var cid struct {
		Secret  string `json:"secret"`
		Version int    `json:"version"`
	}

	if err := json.Unmarshal([]byte(caveatID), &cid); err != nil {
		return nil, errgo.Mask(err)
	}

	if cid.Version != 1 {
		return nil, errgo.Newf("unsupported caveat version %d", cid.Version)
	}

	secret, err := base64.StdEncoding.DecodeString(cid.Secret)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	rootKey, err := d.decrypt(secret)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	m, err := macaroon.New(rootKey, caveatID, d.Location(), macaroon.V1)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if acc != nil {
		m.AddFirstPartyCaveat(d.accountCaveat(acc))
	}
	if !expires.IsZero() {
		m.AddFirstPartyCaveat(d.timeCaveat("expires", expires))
	}
	if !validSince.IsZero() {
		m.AddFirstPartyCaveat(d.timeCaveat("valid_since", validSince))
	}
	if acc != nil && !acc.LastAuth.IsZero() {
		m.AddFirstPartyCaveat(d.timeCaveat("last_auth", acc.LastAuth))
	}

	return m, nil
}

func (d *Discharger) decrypt(secret []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.key == nil {
		return nil, errgo.New("cannot decrypt secret")
	}
	rootKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, d.key, secret, nil)
	if err != nil {
		return nil, errgo.Notef(err, "cannot decrypt secret")
	}
	return rootKey, nil
}

func (d *Discharger) accountCaveat(acc *ssoauth.Account) []byte {
	buf, err := json.Marshal(acc)
	if err != nil {
		panic(err)
	}
	return []byte(fmt.Sprintf("%s|account|%s", d.Location(), base64.StdEncoding.EncodeToString(buf)))
}

func (d *Discharger) timeCaveat(name string, t time.Time) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s", d.Location(), name, t.Format(TimeFormat)))
}

// GetCaveatID gets the caveat ID of the third-party caveat in the given
// macaroon that is addressed to the given discharger. An error is
// returned if there is no caveat or if there is more than one such
// caveat.
func GetCaveatID(d *Discharger, m *macaroon.Macaroon) ([]byte, error) {
	var foundThirdParty bool
	var caveatID []byte
	for _, cav := range m.Caveats() {
		if len(cav.VerificationId) > 0 && cav.Location == d.Location() {
			if foundThirdParty {
				return nil, errgo.New("more than one third party caveat addressed to discharger")
			}
			foundThirdParty = true
			caveatID = cav.Id
		}
	}
	if !foundThirdParty {
		return nil, errgo.New("no third party caveat addressed to discharger")
	}

	return caveatID, nil
}

// Discharge uses the given discharger to create a discharge macaroon for
// the given macaroon and binds that discharge to the original root
// macaroon. If acc, expires or validSince are non-zero then matching
// caveats will be added to the discharge macaroon to represent the given
// values.
func Discharge(d *Discharger, root *macaroon.Macaroon, acc *ssoauth.Account, expires, validSince time.Time) (macaroon.Slice, error) {
	caveatID, err := GetCaveatID(d, root)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	discharge, err := d.Discharge(caveatID, acc, expires, validSince)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	discharge.Bind(root.Signature())
	return macaroon.Slice{root, discharge}, nil
}
