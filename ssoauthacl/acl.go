// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

// Package ssoauthacl provides mechanisms to match accounts to identity
// lists.
package ssoauthacl

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/canonical/ssoauth"
)

// An IdentityMatcher matches an account to a list of identities.
type IdentityMatcher interface {
	// MatchIdentity checks each of the given identities agains the
	// given account. All requested identities that are satisfied by
	// the account are returned, if no identites match then the
	// returned list will be zero-length. The list of matched
	// identities may have the identities in a different order than
	// the list provided. An error is only returned when the Identity
	// matcher cannot determine if the account matches an identity.
	MatchIdentity(ctx context.Context, acc *ssoauth.Account, ids []string) ([]string, error)
}

// An account matcher is an IdentityMatcher that only matches the
// identity identified in the account. The identity must be specified as
// a url of the form "https://{Provider}/+id/{OpenID}".
type AccountMatcher struct{}

// MatchIdentity implements IdentityMatcher.
func (AccountMatcher) MatchIdentity(_ context.Context, acc *ssoauth.Account, ids []string) ([]string, error) {
	accid := fmt.Sprintf("https://%s/+id/%s", acc.Provider, acc.OpenID)
	match := make([]string, 0, 1)

	for _, id := range ids {
		if id == accid {
			match = append(match, id)
		}
	}
	return match, nil
}

// An ACLMatcher is an IdentityMatcher that matches against a list of
// identities by delegating to particular matchers for each identity.
type ACLMatcher map[string]IdentityMatcher

// MatchIdentity implements IdentityMatcher.
//
// Every identity is parsed as a URL, the host is used as the key in the
// ACLMatcher to find the particular IdentityMatcher to use for that
// identity. If the identity is not a valid URL, or there is no
// IdentityMatcher for the host then the account does not match that
// identity. If an IdentityMatcher returns an error it will be bundled
// with any errors from other identity matchers into an ACLMatchError
// structure, this is the only error type returned by this
// IdentityMatcher.
func (m ACLMatcher) MatchIdentity(ctx context.Context, acc *ssoauth.Account, ids []string) ([]string, error) {
	idmap := make(map[string][]string)

	for _, id := range ids {
		u, err := url.Parse(id)
		if err != nil {
			continue
		}
		idmap[u.Host] = append(idmap[u.Host], id)
	}

	matchids := make([]string, 0, len(ids))
	errs := make(map[string]error)
	for k, v := range idmap {
		matcher := m[k]
		if matcher == nil {
			continue
		}
		mids, err := matcher.MatchIdentity(ctx, acc, v)
		matchids = append(matchids, mids...)
		if err != nil {
			errs[k] = err
		}
	}

	if len(errs) > 0 {
		return matchids, &ACLMatchError{Errors: errs}
	}
	return matchids, nil
}

// An ACLMatchError is the error returned from an ACLMatcher if any of
// the IdentityMatchers returns an error.
type ACLMatchError struct {
	Errors map[string]error
}

// Error implements the error interface.
func (e *ACLMatchError) Error() string {
	errs := make([]string, 0, len(e.Errors))
	for k, v := range e.Errors {
		errs = append(errs, fmt.Sprintf("%s: %s", k, v))
	}
	sort.Strings(errs)
	return fmt.Sprintf("some matchers failed [%s]", strings.Join(errs, "; "))
}
