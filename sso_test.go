package ssoauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/canonical/ssoauth"
	"github.com/canonical/ssoauth/ssoauthtest"
)

var discharger = new(ssoauthtest.Discharger)

func TestMacaroon(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	o := bakery.NewOven(bakery.OvenParams{})
	a := ssoauth.New(ssoauth.Params{
		Oven:      o,
		PublicKey: discharger.PublicKey(),
		Location:  discharger.Location(),
	})

	m, err := a.Macaroon(ctx)
	c.Assert(err, qt.IsNil)

	caveatID, err := ssoauthtest.GetCaveatID(discharger, m.M())
	c.Assert(err, qt.IsNil)
	discharge, err := discharger.Discharge(caveatID, nil, time.Time{}, time.Time{})
	c.Assert(err, qt.IsNil)

	discharge.Bind(m.M().Signature())
	ops, _, err := o.VerifyMacaroon(ctx, macaroon.Slice{m.M(), discharge})
	c.Assert(err, qt.IsNil)
	c.Assert(ops, qt.DeepEquals, []bakery.Op{{
		Entity: "ssologin",
		Action: "login",
	}})
}

func TestAuthenticate(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	o := bakery.NewOven(bakery.OvenParams{})
	a := ssoauth.New(ssoauth.Params{
		Oven:      o,
		PublicKey: discharger.PublicKey(),
		Location:  discharger.Location(),
	})

	m, err := a.Macaroon(ctx)
	c.Assert(err, qt.IsNil)

	caveatID, err := ssoauthtest.GetCaveatID(discharger, m.M())
	c.Assert(err, qt.IsNil)
	now := time.Now().UTC()
	expectAccount := ssoauth.Account{
		Provider:    "login.example.com",
		OpenID:      "AAAAAAA",
		Username:    "test-user",
		DisplayName: "Test User",
		Email:       "test@example.com",
		IsVerified:  true,
		LastAuth:    now.Truncate(time.Microsecond),
	}
	discharge, err := discharger.Discharge(
		caveatID,
		&expectAccount,
		now.Add(time.Minute),
		now.Add(-1*time.Minute),
	)
	c.Assert(err, qt.IsNil)

	discharge.Bind(m.M().Signature())
	account, err := a.Authenticate(ctx, macaroon.Slice{m.M(), discharge})
	c.Assert(err, qt.IsNil)
	c.Assert(account, qt.DeepEquals, &expectAccount)
}

func TestAuthenticateNoRoot(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	o := bakery.NewOven(bakery.OvenParams{})
	a := ssoauth.New(ssoauth.Params{
		Oven:      o,
		PublicKey: discharger.PublicKey(),
		Location:  discharger.Location(),
	})

	m, err := a.Macaroon(ctx)
	c.Assert(err, qt.IsNil)

	caveatID, err := ssoauthtest.GetCaveatID(discharger, m.M())
	c.Assert(err, qt.IsNil)
	now := time.Now().UTC()
	expectAccount := ssoauth.Account{
		OpenID:      "AAAAAAA",
		Username:    "test-user",
		DisplayName: "Test User",
		Email:       "test@example.com",
		IsVerified:  true,
		LastAuth:    now.Truncate(time.Microsecond),
	}
	discharge, err := discharger.Discharge(
		caveatID,
		&expectAccount,
		now.Add(time.Minute),
		now.Add(-1*time.Minute),
	)
	c.Assert(err, qt.IsNil)

	discharge.Bind(m.M().Signature())
	account, err := a.Authenticate(ctx, macaroon.Slice{discharge})
	c.Assert(err, qt.ErrorMatches, `verification failed: macaroon not found in storage`)
	c.Assert(errgo.Cause(err), qt.Equals, ssoauth.ErrUnauthorized)
	c.Assert(account, qt.IsNil)
}

func TestAuthenticateIncorrectOp(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	o := bakery.NewOven(bakery.OvenParams{})
	a := ssoauth.New(ssoauth.Params{
		Oven:      o,
		PublicKey: discharger.PublicKey(),
		Location:  discharger.Location(),
	})

	m, err := o.NewMacaroon(ctx, bakery.Version1, nil, bakery.Op{Entity: "test", Action: "test"})
	c.Assert(err, qt.IsNil)

	// Add third-party caveat.
	rootKey := make([]byte, 24)
	_, err = rand.Read(rootKey)
	c.Assert(err, qt.IsNil)
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, discharger.PublicKey(), rootKey, nil)
	c.Assert(err, qt.IsNil)
	var cid struct {
		Secret  string `json:"secret"`
		Version int    `json:"version"`
	}
	cid.Secret = base64.StdEncoding.EncodeToString(encryptedKey)
	cid.Version = 1
	caveatID, err := json.Marshal(cid)
	c.Assert(err, qt.IsNil)
	err = m.M().AddThirdPartyCaveat(rootKey, caveatID, discharger.Location())
	c.Assert(err, qt.IsNil)

	// Create a discharge macaroon.
	discharge, err := discharger.Discharge(caveatID, nil, time.Time{}, time.Time{})
	c.Assert(err, qt.IsNil)

	discharge.Bind(m.M().Signature())
	account, err := a.Authenticate(ctx, macaroon.Slice{m.M(), discharge})
	c.Assert(err, qt.ErrorMatches, `invalid macaroon`)
	c.Assert(errgo.Cause(err), qt.Equals, ssoauth.ErrUnauthorized)
	c.Assert(account, qt.IsNil)
}

var authenticateUnauthorizedTests = []struct {
	name        string
	caveats     []string
	expectError string
}{{
	name: "invalid-account-base64",
	caveats: []string{
		discharger.Location() + "|account|@@@@",
	},
	expectError: `cannot parse caveat "` + discharger.Location() + `\|account\|@@@@": illegal base64 data at input byte 0`,
}, {
	name: "invalid-account-json",
	caveats: []string{
		discharger.Location() + "|account|AA==",
	},
	expectError: `cannot parse caveat "` + discharger.Location() + `\|account\|AA==": invalid character '\\x00' looking for beginning of value`,
}, {
	name: "multiple-accounts",
	caveats: []string{
		discharger.Location() + "|account|eyJvcGVuaWQiOiJBQUFBQUFBIn0=",
		discharger.Location() + "|account|eyJvcGVuaWQiOiJBQUFBQUFBIn0=",
	},
	expectError: `duplicate caveat "` + discharger.Location() + `\|account\|.*`,
}, {
	name: "multiple-last-auth",
	caveats: []string{
		discharger.Location() + "|last_auth|2019-01-01T00:00:00.000000",
		discharger.Location() + "|last_auth|2019-01-01T00:00:00.000000",
	},
	expectError: `duplicate caveat "` + discharger.Location() + `\|last_auth\|.*`,
}, {
	name: "invalid-last-auth",
	caveats: []string{
		discharger.Location() + "|last_auth|yesterday",
	},
	expectError: `cannot parse caveat "` + discharger.Location() + `\|last_auth\|yesterday": .*`,
}, {
	name: "expired",
	caveats: []string{
		discharger.Location() + "|expires|2000-01-01T00:00:00.000000",
	},
	expectError: `macaroon expired`,
}, {
	name: "invalid-expires",
	caveats: []string{
		discharger.Location() + "|expires|yesterday",
	},
	expectError: `cannot parse caveat "` + discharger.Location() + `\|expires\|yesterday": .*`,
}, {
	name: "not-yet-valid",
	caveats: []string{
		discharger.Location() + "|valid_since|3000-01-01T00:00:00.000000",
	},
	expectError: `macaroon not yet valid`,
}, {
	name: "invalid-valid-since",
	caveats: []string{
		discharger.Location() + "|valid_since|yesterday",
	},
	expectError: `cannot parse caveat "` + discharger.Location() + `\|valid_since\|yesterday": .*`,
}, {
	name: "standard-bakery-caveat",
	caveats: []string{
		checkers.TimeBeforeCaveat(time.Now().Add(-1 * time.Minute)).Condition,
	},
	expectError: `caveat "time-before .*" not satisfied: macaroon has expired`,
}}

func TestAuthenticateUnauthorized(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	o := bakery.NewOven(bakery.OvenParams{})
	a := ssoauth.New(ssoauth.Params{
		Oven:      o,
		PublicKey: discharger.PublicKey(),
		Location:  discharger.Location(),
	})

	m, err := a.Macaroon(ctx)
	c.Assert(err, qt.IsNil)

	caveatID, err := ssoauthtest.GetCaveatID(discharger, m.M())
	c.Assert(err, qt.IsNil)

	for _, test := range authenticateUnauthorizedTests {
		test := test
		c.Run(test.name, func(c *qt.C) {
			ctx := context.Background()

			// Create a discharge macaroon.
			discharge, err := discharger.Discharge(caveatID, nil, time.Time{}, time.Time{})
			c.Assert(err, qt.IsNil)
			for _, cav := range test.caveats {
				discharge.AddFirstPartyCaveat([]byte(cav))
			}
			discharge.Bind(m.M().Signature())
			account, err := a.Authenticate(ctx, macaroon.Slice{m.M(), discharge})
			c.Assert(err, qt.ErrorMatches, test.expectError)
			c.Assert(errgo.Cause(err), qt.Equals, ssoauth.ErrUnauthorized)
			c.Assert(account, qt.IsNil)
		})
	}
}

func TestUnknownSSOFirstPartyCaveats(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	o := bakery.NewOven(bakery.OvenParams{})
	a := ssoauth.New(ssoauth.Params{
		Oven:      o,
		PublicKey: discharger.PublicKey(),
		Location:  discharger.Location(),
	})

	m, err := a.Macaroon(ctx)
	c.Assert(err, qt.IsNil)

	caveatID, err := ssoauthtest.GetCaveatID(discharger, m.M())
	c.Assert(err, qt.IsNil)

	// Create a discharge macaroon.
	now := time.Now().UTC()
	expectAccount := ssoauth.Account{
		Provider:    "login.example.com",
		OpenID:      "AAAAAAA",
		Username:    "test-user",
		DisplayName: "Test User",
		Email:       "test@example.com",
		IsVerified:  true,
		LastAuth:    now.Truncate(time.Microsecond),
	}
	discharge, err := discharger.Discharge(caveatID, &expectAccount, now.Add(time.Minute), now.Add(-1*time.Minute))
	c.Assert(err, qt.IsNil)
	discharge.AddFirstPartyCaveat([]byte(discharge.Location() + "|unknown|unknown"))

	discharge.Bind(m.M().Signature())
	account, err := a.Authenticate(ctx, macaroon.Slice{m.M(), discharge})
	c.Assert(err, qt.IsNil)

	c.Assert(account, qt.DeepEquals, &expectAccount)
}

func TestMacaroonRoundTrip(t *testing.T) {
	c := qt.New(t)

	var rk1 [24]byte
	_, err := rand.Read(rk1[:])
	c.Assert(err, qt.IsNil)

	m, err := macaroon.New(rk1[:], []byte("test-key"), "", macaroon.V2)
	c.Assert(err, qt.IsNil)

	var rk2 [24]byte
	_, err = rand.Read(rk2[:])
	c.Assert(err, qt.IsNil)
	err = ssoauth.AddThirdPartyCaveat(m, rk2[:], discharger.Location(), discharger.PublicKey())
	c.Assert(err, qt.IsNil)

	var caveatID []byte
	for _, cav := range m.Caveats() {
		if cav.VerificationId == nil || cav.Location != discharger.Location() {
			continue
		}

		caveatID = cav.Id
	}

	now := time.Now().UTC()
	expectAccount := ssoauth.Account{
		Provider:    "login.example.com",
		OpenID:      "AAAAAAA",
		Username:    "test-user",
		DisplayName: "Test User",
		Email:       "test@example.com",
		IsVerified:  true,
		LastAuth:    now.Truncate(time.Microsecond),
	}
	discharge, err := discharger.Discharge(caveatID, &expectAccount, now.Add(time.Minute), now.Add(-1*time.Minute))
	c.Assert(err, qt.IsNil)
	discharge.Bind(m.Signature())

	var acc ssoauth.Account
	err = m.Verify(rk1[:], ssoauth.CaveatChecker(discharger.Location(), &acc), []*macaroon.Macaroon{discharge})
	c.Assert(err, qt.IsNil)

	c.Assert(acc, qt.DeepEquals, expectAccount)
}
