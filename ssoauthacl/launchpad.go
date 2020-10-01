// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package ssoauthacl

import (
	"context"

	"golang.org/x/sync/singleflight"
	"gopkg.in/errgo.v1"
	"launchpad.net/lpad"

	"github.com/canonical/ssoauth"
)

// A LaunchpadTeamMatcher is an IdentityMatcher that matches against an
// account's launchpad teams.
type LaunchpadTeamMatcher struct {
	// APIBase holds the base address of the launchpad API.
	// If this is not set then lpad.Production will be used.
	APIBase lpad.APIBase

	// Auth holds an authentication to use when querying the
	// launchpad API. If Auth is nil an anonymous authentication will
	// be used.
	Auth lpad.Auth

	// LaunchpadOpenID holds the function used to determine the
	// launchpad openid string from an account. If this is nil then
	// DefaultLaunchpadOpenID is used.
	LaunchpadOpenID func(*ssoauth.Account) string

	// Cache is used to store lists of launchpad teams indexed by
	// launchpad open ID. If Cache is nil then all requests will go
	// directly to the launchpad API.
	Cache Cache

	// SingleflightGroup is used to prevent multiple concurrent
	// requests being made for the same account. If this is nil then
	// no such protection will be used.
	SingleflightGroup *singleflight.Group
}

// MatchIdentity implements IdentityMatcher.
func (m LaunchpadTeamMatcher) MatchIdentity(ctx context.Context, acc *ssoauth.Account, ids []string) ([]string, error) {
	oidf := DefaultLaunchpadOpenID
	if m.LaunchpadOpenID != nil {
		oidf = m.LaunchpadOpenID
	}
	oid := oidf(acc)
	if oid == "" {
		// The account cannot be mapped to a launchpad OpenID, so
		// it cannot match any of the IDs.
		return nil, nil
	}

	var teams []string
	var err error
	if m.SingleflightGroup != nil {
		ch := m.SingleflightGroup.DoChan(oid, func() (interface{}, error) {
			return m.getLaunchpadTeams(ctx, oid)
		})
		select {
		case r := <-ch:
			teams, _ = r.Val.([]string)
			err = r.Err
		case <-ctx.Done():
			err = ctx.Err()
		}
	} else {
		teams, err = m.getLaunchpadTeams(ctx, oid)
	}

	rids := make([]string, 0, len(ids))
	for _, id := range ids {
		for _, t := range teams {
			if id == t {
				rids = append(rids, id)
			}
		}
	}
	return rids, errgo.Mask(err, errgo.Is(context.Canceled), errgo.Is(context.DeadlineExceeded))
}

func (m LaunchpadTeamMatcher) getLaunchpadTeams(ctx context.Context, openID string) ([]string, error) {
	if m.Cache != nil {
		if teams, ok := m.Cache.Get(openID); ok {
			return teams, nil
		}
	}

	auth := m.Auth
	if auth == nil {
		auth = &lpad.OAuth{Consumer: "github.com/canonical/ssoauth/ssoauthacl", Anonymous: true}
	}
	apiBase := m.APIBase
	if apiBase == "" {
		apiBase = lpad.Production
	}
	root, err := lpad.Login(apiBase, auth)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	v, err := root.Location("/people").Get(lpad.Params{"ws.op": "getByOpenIDIdentifier", "identifier": openID})
	if errgo.Cause(err) == lpad.ErrNotFound {
		// If the user is not found they can't be in any teams.
		return nil, nil
	}
	if err != nil {
		return nil, errgo.Mask(err)
	}
	v, err = v.Link("super_teams_collection_link").Get(nil)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	teams := make([]string, v.TotalSize())
	var i int
	err = v.For(func(v *lpad.Value) error {
		if name := v.StringField("web_link"); name != "" {
			teams[i] = name
			i++
		}
		return nil
	})
	if m.Cache != nil && err == nil {
		m.Cache.Add(openID, teams)
	}
	return teams[:i], errgo.Mask(err)
}

// DefaultLaunchpadOpenID is the default mapping from an ssoauth.Account
// to a launchpad OpenID.
func DefaultLaunchpadOpenID(acc *ssoauth.Account) string {
	switch acc.Provider {
	case "login.launchpad.net", "login.ubuntu.com":
		return "https://login.launchpad.net/+id/" + acc.OpenID
	case "login-lp.staging.ubuntu.com", "login.staging.ubuntu.com":
		return "https://login-lp.staging.ubuntu.com/+id/" + acc.OpenID
	default:
		return ""
	}
}

// A Cache implementation can be used by a LaunchpadTeamMatcher to store
// launchpad team lists, rather then using the API every time.
type Cache interface {
	// Add stores the given value in the cache with the given key.
	Add(key string, value []string)

	// Get retrieves the item with the given key from the cache, if
	// available.
	Get(key string) ([]string, bool)
}
