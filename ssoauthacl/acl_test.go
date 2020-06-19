package ssoauthacl_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/errgo.v1"

	"github.com/canonical/ssoauth"
	"github.com/canonical/ssoauth/ssoauthacl"
)

func TestIdentityMatcher(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	acc := &ssoauth.Account{
		Provider: "login.example.com",
		OpenID:   "AAAAAAA",
	}

	var m ssoauthacl.IdentityMatcher = ssoauthacl.AccountMatcher{}
	ids, err := m.MatchIdentity(ctx, acc, []string{"https://login.example.com/+id/AAAAAAA", "https://login.example.com/+id/BBBBBBB"})
	c.Check(err, qt.IsNil)
	c.Check(ids, qt.DeepEquals, []string{"https://login.example.com/+id/AAAAAAA"})

	ids, err = m.MatchIdentity(ctx, acc, []string{"https://login.example.com/+id/CCCCCCC", "https://login.example.com/+id/DDDDDDD"})
	c.Check(ids, qt.HasLen, 0)
}

func TestACLMatcher(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	acc := &ssoauth.Account{
		Provider: "1.example.com",
		OpenID:   "AAAAAAA",
	}

	var m ssoauthacl.IdentityMatcher = ssoauthacl.ACLMatcher{
		"1.example.com": ssoauthacl.AccountMatcher{},
		"2.example.com": ssoauthacl.AccountMatcher{},
	}

	ids, err := m.MatchIdentity(ctx, acc, []string{
		"https://1.example.com/+id/AAAAAAA",
		"https://2.example.com/+id/AAAAAAA",
		"https://3.example.com/+id/AAAAAAA",
		"::AAAAAAA",
	})
	c.Check(err, qt.IsNil)
	c.Check(ids, qt.DeepEquals, []string{"https://1.example.com/+id/AAAAAAA"})
}

func TestACLMatcherError(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	acc := &ssoauth.Account{
		Provider: "2.example.com",
		OpenID:   "AAAAAAA",
	}

	var m ssoauthacl.IdentityMatcher = ssoauthacl.ACLMatcher{
		"1.example.com": errorMatcher{errgo.New("error 1")},
		"2.example.com": ssoauthacl.AccountMatcher{},
		"3.example.com": errorMatcher{errgo.New("error 3")},
	}

	ids, err := m.MatchIdentity(ctx, acc, []string{
		"https://3.example.com/+id/AAAAAAA",
		"https://1.example.com/+id/AAAAAAA",
		"https://2.example.com/+id/AAAAAAA",
	})
	c.Check(err, qt.ErrorMatches, `some matchers failed \[1.example.com: error 1; 3.example.com: error 3\]`)
	_, ok := err.(*ssoauthacl.ACLMatchError)
	c.Check(ok, qt.Equals, true)
	c.Check(ids, qt.DeepEquals, []string{"https://2.example.com/+id/AAAAAAA"})
}

type errorMatcher struct {
	err error
}

func (m errorMatcher) MatchIdentity(context.Context, *ssoauth.Account, []string) ([]string, error) {
	return nil, m.err
}
