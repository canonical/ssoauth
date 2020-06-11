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
	//
	// Note: there is no known documentation for this format, but the
	// relevent sso code can be found in
	// https://bazaar.launchpad.net/~ubuntuone-pqm-team/canonical-identity-provider/trunk/view/head:/src/identityprovider/auth.py
	// and an example target service can be found in
	// https://bazaar.launchpad.net/~ubuntuone-pqm-team/software-center-agent/trunk/view/head:/src/devportal/api/auth.py.
	rootKey := make([]byte, 24)
	if _, err = rand.Read(rootKey); err != nil {
		return nil, errgo.Mask(err)
	}
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, a.p.PublicKey, rootKey[:], nil)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	var cid struct {
		Secret  string `json:"secret"`
		Version int    `json:"version"`
	}
	cid.Secret = base64.StdEncoding.EncodeToString(encryptedKey)
	cid.Version = 1
	caveatID, err := json.Marshal(cid)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if err := m.M().AddThirdPartyCaveat(rootKey, caveatID, a.p.Location); err != nil {
		return nil, errgo.Notef(err, "cannot create macaroon")
	}

	return m, nil
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
	var seenAccount, seenLastAuth bool

	stdChecker := checkers.New(nil)
	for _, cond := range conditions {
		if !strings.HasPrefix(cond, a.p.Location+"|") {
			if err := stdChecker.CheckFirstPartyCaveat(ctx, cond); err != nil {
				return nil, errgo.WithCausef(err, ErrUnauthorized, "")
			}
			continue
		}

		parts := strings.SplitN(cond, "|", 3)
		switch parts[1] {
		case "account":
			// account is a declarative caveat the the SSO
			// server will only add one of. If we have
			// already seen one then reject the macaroon.
			if seenAccount {
				return nil, errgo.WithCausef(nil, ErrUnauthorized, "duplicate caveat %q", cond)
			}
			seenAccount = true
			b, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil {
				return nil, errgo.WithCausef(err, ErrUnauthorized, "cannot parse caveat %q", cond)
			}
			if err := json.Unmarshal(b, &account); err != nil {
				return nil, errgo.WithCausef(err, ErrUnauthorized, "cannot parse caveat %q", cond)
			}
		case "expires":
			// Ensure that now is before the macaroon expires.
			t, err := time.Parse(timeFormat, parts[2])
			if err != nil {
				return nil, errgo.WithCausef(err, ErrUnauthorized, "cannot parse caveat %q", cond)
			}
			if !time.Now().Before(t) {
				return nil, errgo.WithCausef(nil, ErrUnauthorized, "macaroon expired")
			}
		case "last_auth":
			// last_auth is a declarative caveat the the SSO
			// server will only add one of. If we have
			// already seen one then reject the macaroon.
			if seenLastAuth {
				return nil, errgo.WithCausef(nil, ErrUnauthorized, "duplicate caveat %q", cond)
			}
			seenLastAuth = true
			account.LastAuth, err = time.Parse(timeFormat, parts[2])
			if err != nil {
				return nil, errgo.WithCausef(err, ErrUnauthorized, "cannot parse caveat %q", cond)
			}
		case "valid_since":
			// Ensure that now is after valid_since.
			t, err := time.Parse(timeFormat, parts[2])
			if err != nil {
				return nil, errgo.WithCausef(err, ErrUnauthorized, "cannot parse caveat %q", cond)
			}
			if !time.Now().After(t) {
				return nil, errgo.WithCausef(nil, ErrUnauthorized, "macaroon not yet valid")
			}
		default:
			// Ideally we would fail here, but there is
			// currently no guarantee that SSO won't add
			// additional first-party caveats to the
			// discharge macaroon (see
			// https://bugs.launchpad.net/canonical-identity-provider/+bug/1814563).
			// For now just log the unexpected caveat.
			log.Printf("unexpected SSO caveat detected %q", cond)
		}
	}

	return &account, nil
}

// Account contains the details of the authenticated user that Ubuntu
// SSO added to the discharge macaroon.
type Account struct {
	OpenID      string    `json:"openid"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayname"`
	Email       string    `json:"email"`
	IsVerified  bool      `json:"is_verified"`
	LastAuth    time.Time `json:"-"`
}

// Allow checks if the Account is included in the given ACL.
func (a Account) Allow(_ context.Context, acl []string) (bool, error) {
	aclID := "https://login.ubuntu.com/+id/" + a.OpenID
	for _, a := range acl {
		if a == aclID {
			return true, nil
		}
	}
	return false, nil
}
