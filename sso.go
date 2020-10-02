// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

// Package ssoauth implements macaroon based authentication with
// Canonical SSO.
package ssoauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"

	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	macaroon "gopkg.in/macaroon.v2"
)

const (
	timeFormat = "2006-01-02T15:04:05.000000"
	expireTime = 7 * 24 * time.Hour
)

var ssoLoginOp = bakery.Op{
	Entity: "ssologin",
	Action: "login",
}

var ErrUnauthorized = errgo.New("unauthorized")

// An Authenticator is used to mint macaroons with a third-party caveat
// addressed to a canonical SSO provider and authenticate responses.
type Authenticator struct {
	p Params
}

type Params struct {
	// Oven contains the Oven instance that issues the macaroons.
	Oven *bakery.Oven

	// Location contains the Ubuntu SSO location that the macaroons
	// are addressed to.
	Location string

	// PublicKey contains the public key of the Ubuntu SSO server to
	// which the third-party caveat will be addressed.
	PublicKey *rsa.PublicKey
}

// New creates a new Authenticator.
func New(p Params) *Authenticator {
	return &Authenticator{
		p: p,
	}
}

// Macaroon creates a new macaroon with a third party caveat addressed to
// the configured SSO server. Once discharged, the macaroon can be used
// to authorize a call to the Authenticate method.
func (a *Authenticator) Macaroon(ctx context.Context) (*bakery.Macaroon, error) {
	m, err := a.p.Oven.NewMacaroon(
		ctx,
		bakery.Version1,
		[]checkers.Caveat{
			checkers.TimeBeforeCaveat(time.Now().Add(expireTime)),
		},
		ssoLoginOp,
	)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	// SSO compatible third-party caveats use a different convention
	// to standard bakery macaroons so it has to be created and
	// attached in a custom manner.
	rootKey := make([]byte, 24)
	if _, err = rand.Read(rootKey); err != nil {
		return nil, errgo.Mask(err)
	}

	if err := AddThirdPartyCaveat(m.M(), rootKey[:], a.p.Location, a.p.PublicKey); err != nil {
		return nil, errgo.Mask(err)
	}

	return m, nil
}

// AddThirdPartyCaveat adds a third-party caveat to the given macaroon in
// the format understood by the SSO server.
func AddThirdPartyCaveat(m *macaroon.Macaroon, rootKey []byte, location string, pk *rsa.PublicKey) error {
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pk, rootKey, nil)
	if err != nil {
		return errgo.Mask(err)
	}
	var cid = struct {
		Secret  string `json:"secret"`
		Version int    `json:"version"`
	}{
		Secret:  base64.StdEncoding.EncodeToString(encryptedKey),
		Version: 1,
	}
	caveatID, err := json.Marshal(cid)
	if err != nil {
		return errgo.Mask(err)
	}
	return errgo.Mask(m.AddThirdPartyCaveat(rootKey, caveatID, location))
}

// Authenticate checks that the given macaroon slice is a valid
// discharged SSO macaroon and returns the user details associated with
// the macaroon, if any. If given macaroons are not valid then an error
// with a cause of ErrUnauthorized is returned.
func (a *Authenticator) Authenticate(ctx context.Context, ms macaroon.Slice) (*Account, error) {
	ops, conditions, err := a.p.Oven.VerifyMacaroon(ctx, ms)
	if err != nil {
		if _, ok := err.(*bakery.VerificationError); ok {
			return nil, errgo.WithCausef(err, ErrUnauthorized, "")
		}
		return nil, errgo.Mask(err)
	}

	if len(ops) != 1 || ops[0] != ssoLoginOp {
		return nil, errgo.WithCausef(nil, ErrUnauthorized, "invalid macaroon")
	}

	var account Account

	ssoChecker := CaveatChecker(a.p.Location, &account)
	stdChecker := checkers.New(nil)
	for _, cond := range conditions {
		if err := ssoChecker(cond); err != nil {
			if err == ErrUnsupportedCaveat {
				err = stdChecker.CheckFirstPartyCaveat(ctx, cond)
			}
			if err != nil {
				return nil, errgo.WithCausef(err, ErrUnauthorized, "")
			}
		}
	}

	return &account, nil
}

// Account contains the details of the authenticated user that Ubuntu
// SSO added to the discharge macaroon.
type Account struct {
	Provider    string    `json:"-"`
	OpenID      string    `json:"openid"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayname"`
	Email       string    `json:"email"`
	IsVerified  bool      `json:"is_verified"`
	LastAuth    time.Time `json:"-"`
}

// ErrUnsupportedCaveat is returned from the function created in
// CaveatChecker when the caveat is not understood by the checker.
var ErrUnsupportedCaveat = errgo.New("unsupported caveat")

// CaveatChecker creates a function which verifies first-party caveats
// added by the SSO server at the given location. Account information
// returned from the SSO server will be stored in the given Account. The
// returned function is suitable for using asthe check parameter with the
// Verify method of macaroon.Macaroon. If any provided caveat is not
// supported by this checker then an ErrUnsupportedCaveat error will be
// returned.
func CaveatChecker(location string, acc *Account) func(caveatID string) error {
	if acc == nil {
		acc = new(Account)
	}
	return func(caveatID string) error {
		parts := strings.SplitN(caveatID, "|", 3)
		if len(parts) < 2 || parts[0] != location {
			return ErrUnsupportedCaveat
		}
		switch parts[1] {
		case "account":
			// account is a declarative caveat that the SSO
			// server will only add one of. If we have
			// already seen one then reject the macaroon.
			if acc.Provider != "" {
				return errgo.Newf("duplicate caveat %q", caveatID)
			}
			acc.Provider = parts[0]
			if len(parts) < 3 {
				return errgo.Newf("malformed caveat %q", caveatID)
			}
			b, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil {
				return errgo.Notef(err, "cannot parse caveat %q", caveatID)
			}
			if err := json.Unmarshal(b, &acc); err != nil {
				return errgo.Notef(err, "cannot parse caveat %q", caveatID)
			}
		case "expires":
			if len(parts) < 3 {
				return errgo.Newf("malformed caveat %q", caveatID)
			}
			// Ensure that now is before the macaroon expires.
			t, err := time.Parse(timeFormat, parts[2])
			if err != nil {
				return errgo.Notef(err, "cannot parse caveat %q", caveatID)
			}
			if !time.Now().Before(t) {
				return errgo.New("macaroon expired")
			}
		case "last_auth":
			// last_auth is a declarative caveat the the SSO
			// server will only add one of. If we have
			// already seen one then reject the macaroon.
			if !acc.LastAuth.IsZero() {
				return errgo.Newf("duplicate caveat %q", caveatID)
			}
			if len(parts) < 3 {
				return errgo.Newf("malformed caveat %q", caveatID)
			}
			var err error
			acc.LastAuth, err = time.Parse(timeFormat, parts[2])
			if err != nil {
				return errgo.Notef(err, "cannot parse caveat %q", caveatID)
			}
		case "valid_since":
			// Ensure that now is after valid_since.
			if len(parts) < 3 {
				return errgo.Newf("malformed caveat %q", caveatID)
			}
			t, err := time.Parse(timeFormat, parts[2])
			if err != nil {
				return errgo.Notef(err, "cannot parse caveat %q", caveatID)
			}
			if !time.Now().After(t) {
				return errgo.New("macaroon not yet valid")
			}
		default:
			// Ideally we would fail here, but there is
			// currently no guarantee that SSO won't add
			// additional first-party caveats to the
			// discharge macaroon. For now just log the
			// unexpected caveat.
			log.Printf("unexpected SSO caveat detected %q", caveatID)
		}

		return nil
	}
}
