package ssoauthacl_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"golang.org/x/sync/singleflight"
	"gopkg.in/errgo.v1"
	"launchpad.net/lpad"

	"github.com/canonical/ssoauth"
	"github.com/canonical/ssoauth/ssoauthacl"
)

func TestLaunchpadTeamMatcher(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	c.Cleanup(srv.Close)

	var m ssoauthacl.IdentityMatcher = ssoauthacl.LaunchpadTeamMatcher{
		APIBase: lpad.APIBase(srv.URL),
	}

	acc := &ssoauth.Account{
		Provider: "login.ubuntu.com",
		OpenID:   "AAAAAAA",
	}

	mux.HandleFunc("/people", func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		c.Check(req.Method, qt.Equals, "GET")
		c.Check(req.Form.Get("ws.op"), qt.Equals, "getByOpenIDIdentifier")
		c.Check(req.Form.Get("identifier"), qt.Equals, "https://login.launchpad.net/+id/AAAAAAA")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"name": "test", "super_teams_collection_link": "http://%s/test/super_teams"}`, req.Host)
	})

	mux.HandleFunc("/test/super_teams", func(w http.ResponseWriter, req *http.Request) {
		c.Check(req.Method, qt.Equals, "GET")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"total_size":3,"start":0,"entries": [{"web_link": "https://launchpad.net/~test1"},{"web_link":"https://launchpad.net/~test2"}]}`)
	})

	ids, err := m.MatchIdentity(ctx, acc, []string{
		"https://launchpad.net/~test1",
		"https://launchpad.net/~test2",
		"https://launchpad.net/~test3",
	})

	c.Check(err, qt.IsNil)
	sort.Strings(ids)
	c.Check(ids, qt.DeepEquals, []string{
		"https://launchpad.net/~test1",
		"https://launchpad.net/~test2",
	})
}

func TestLaunchpadTeamMatcherUnsupportedAccount(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	c.Cleanup(srv.Close)

	var m ssoauthacl.IdentityMatcher = ssoauthacl.LaunchpadTeamMatcher{
		APIBase: lpad.APIBase(srv.URL),
	}

	acc := &ssoauth.Account{
		Provider: "login.example.com",
		OpenID:   "AAAAAAA",
	}

	ids, err := m.MatchIdentity(ctx, acc, []string{
		"https://launchpad.net/~test1",
		"https://launchpad.net/~test2",
		"https://launchpad.net/~test3",
	})

	c.Check(err, qt.IsNil)
	c.Check(ids, qt.HasLen, 0)
}

func TestLaunchpadTeamMatcherSingleFlight(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	c.Cleanup(srv.Close)

	var m ssoauthacl.IdentityMatcher = ssoauthacl.LaunchpadTeamMatcher{
		APIBase:           lpad.APIBase(srv.URL),
		SingleflightGroup: new(singleflight.Group),
	}

	acc := &ssoauth.Account{
		Provider: "login.ubuntu.com",
		OpenID:   "AAAAAAA",
	}

	ch := make(chan struct{})
	var peopleRequests uint32
	mux.HandleFunc("/people", func(w http.ResponseWriter, req *http.Request) {
		atomic.AddUint32(&peopleRequests, 1)
		ch <- struct{}{}
		time.Sleep(10 * time.Millisecond)
		req.ParseForm()
		c.Check(req.Method, qt.Equals, "GET")
		c.Check(req.Form.Get("ws.op"), qt.Equals, "getByOpenIDIdentifier")
		c.Check(req.Form.Get("identifier"), qt.Equals, "https://login.launchpad.net/+id/AAAAAAA")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"name": "test", "super_teams_collection_link": "http://%s/test/super_teams"}`, req.Host)
	})

	var teamRequests uint32
	mux.HandleFunc("/test/super_teams", func(w http.ResponseWriter, req *http.Request) {
		atomic.AddUint32(&teamRequests, 1)
		c.Check(req.Method, qt.Equals, "GET")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"total_size":3,"start":0,"entries": [{"web_link": "https://launchpad.net/~test1"},{"web_link":"https://launchpad.net/~test2"}]}`)
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		ids, err := m.MatchIdentity(ctx, acc, []string{
			"https://launchpad.net/~test1",
			"https://launchpad.net/~test2",
			"https://launchpad.net/~test3",
		})
		c.Check(err, qt.IsNil)
		sort.Strings(ids)
		c.Check(ids, qt.DeepEquals, []string{
			"https://launchpad.net/~test1",
			"https://launchpad.net/~test2",
		})
	}()
	<-ch
	go func() {
		defer wg.Done()
		ids, err := m.MatchIdentity(ctx, acc, []string{
			"https://launchpad.net/~test1",
			"https://launchpad.net/~test2",
			"https://launchpad.net/~test3",
		})
		c.Check(err, qt.IsNil)
		sort.Strings(ids)
		c.Check(ids, qt.DeepEquals, []string{
			"https://launchpad.net/~test1",
			"https://launchpad.net/~test2",
		})
	}()

	wg.Wait()
	c.Check(atomic.LoadUint32(&peopleRequests), qt.Equals, uint32(1))
	c.Check(atomic.LoadUint32(&teamRequests), qt.Equals, uint32(1))
}

func TestLaunchpadTeamMatcherSingleFlightCanceled(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	c.Cleanup(srv.Close)

	var m ssoauthacl.IdentityMatcher = ssoauthacl.LaunchpadTeamMatcher{
		APIBase:           lpad.APIBase(srv.URL),
		SingleflightGroup: new(singleflight.Group),
	}

	acc := &ssoauth.Account{
		Provider: "login.ubuntu.com",
		OpenID:   "AAAAAAA",
	}

	ch := make(chan struct{})
	var peopleRequests uint32
	mux.HandleFunc("/people", func(w http.ResponseWriter, req *http.Request) {
		atomic.AddUint32(&peopleRequests, 1)
		ch <- struct{}{}
		time.Sleep(10 * time.Millisecond)
		req.ParseForm()
		c.Check(req.Method, qt.Equals, "GET")
		c.Check(req.Form.Get("ws.op"), qt.Equals, "getByOpenIDIdentifier")
		c.Check(req.Form.Get("identifier"), qt.Equals, "https://login.launchpad.net/+id/AAAAAAA")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"name": "test", "super_teams_collection_link": "http://%s/test/super_teams"}`, req.Host)
	})

	var teamRequests uint32
	mux.HandleFunc("/test/super_teams", func(w http.ResponseWriter, req *http.Request) {
		atomic.AddUint32(&teamRequests, 1)
		c.Check(req.Method, qt.Equals, "GET")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"total_size":3,"start":0,"entries": [{"web_link": "https://launchpad.net/~test1"},{"web_link":"https://launchpad.net/~test2"}]}`)
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		ids, err := m.MatchIdentity(ctx, acc, []string{
			"https://launchpad.net/~test1",
			"https://launchpad.net/~test2",
			"https://launchpad.net/~test3",
		})
		c.Check(err, qt.IsNil)
		sort.Strings(ids)
		c.Check(ids, qt.DeepEquals, []string{
			"https://launchpad.net/~test1",
			"https://launchpad.net/~test2",
		})
	}()
	<-ch
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		ids, err := m.MatchIdentity(ctx, acc, []string{
			"https://launchpad.net/~test1",
			"https://launchpad.net/~test2",
			"https://launchpad.net/~test3",
		})
		c.Check(errgo.Cause(err), qt.Equals, context.Canceled)
		c.Check(ids, qt.HasLen, 0)
	}()

	wg.Wait()
	c.Check(atomic.LoadUint32(&peopleRequests), qt.Equals, uint32(1))
	c.Check(atomic.LoadUint32(&teamRequests), qt.Equals, uint32(1))
}

func TestLaunchpadTeamMatcherCache(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	c.Cleanup(srv.Close)

	var m ssoauthacl.IdentityMatcher = ssoauthacl.LaunchpadTeamMatcher{
		APIBase: lpad.APIBase(srv.URL),
		Cache:   make(testCache),
	}

	acc := &ssoauth.Account{
		Provider: "login.ubuntu.com",
		OpenID:   "AAAAAAA",
	}

	var peopleRequests uint32
	mux.HandleFunc("/people", func(w http.ResponseWriter, req *http.Request) {
		atomic.AddUint32(&peopleRequests, 1)
		req.ParseForm()
		c.Check(req.Method, qt.Equals, "GET")
		c.Check(req.Form.Get("ws.op"), qt.Equals, "getByOpenIDIdentifier")
		c.Check(req.Form.Get("identifier"), qt.Equals, "https://login.launchpad.net/+id/AAAAAAA")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"name": "test", "super_teams_collection_link": "http://%s/test/super_teams"}`, req.Host)
	})

	var teamRequests uint32
	mux.HandleFunc("/test/super_teams", func(w http.ResponseWriter, req *http.Request) {
		atomic.AddUint32(&teamRequests, 1)
		c.Check(req.Method, qt.Equals, "GET")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"total_size":3,"start":0,"entries": [{"web_link": "https://launchpad.net/~test1"},{"web_link":"https://launchpad.net/~test2"}]}`)
	})

	ids, err := m.MatchIdentity(ctx, acc, []string{
		"https://launchpad.net/~test1",
		"https://launchpad.net/~test2",
		"https://launchpad.net/~test3",
	})
	c.Check(err, qt.IsNil)
	sort.Strings(ids)
	c.Check(ids, qt.DeepEquals, []string{
		"https://launchpad.net/~test1",
		"https://launchpad.net/~test2",
	})

	ids, err = m.MatchIdentity(ctx, acc, []string{
		"https://launchpad.net/~test1",
		"https://launchpad.net/~test2",
		"https://launchpad.net/~test3",
	})
	c.Check(err, qt.IsNil)
	sort.Strings(ids)
	c.Check(ids, qt.DeepEquals, []string{
		"https://launchpad.net/~test1",
		"https://launchpad.net/~test2",
	})

	c.Check(atomic.LoadUint32(&peopleRequests), qt.Equals, uint32(1))
	c.Check(atomic.LoadUint32(&teamRequests), qt.Equals, uint32(1))
}

type testCache map[string][]string

func (c testCache) Add(key string, value []string) {
	c[key] = value
}

func (c testCache) Get(key string) ([]string, bool) {
	v, ok := c[key]
	return v, ok
}

func TestLaunchpadTeamMatcherNotFound(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	c.Cleanup(srv.Close)

	var m ssoauthacl.IdentityMatcher = ssoauthacl.LaunchpadTeamMatcher{
		APIBase: lpad.APIBase(srv.URL),
	}

	acc := &ssoauth.Account{
		Provider: "login.ubuntu.com",
		OpenID:   "AAAAAAA",
	}

	mux.HandleFunc("/people", func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		c.Check(req.Method, qt.Equals, "GET")
		c.Check(req.Form.Get("ws.op"), qt.Equals, "getByOpenIDIdentifier")
		c.Check(req.Form.Get("identifier"), qt.Equals, "https://login.launchpad.net/+id/AAAAAAA")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `null`)
	})

	mux.HandleFunc("/test/super_teams", func(w http.ResponseWriter, req *http.Request) {
		c.Check(req.Method, qt.Equals, "GET")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"total_size":3,"start":0,"entries": [{"web_link": "https://launchpad.net/~test1"},{"web_link":"https://launchpad.net/~test2"}]}`)
	})

	ids, err := m.MatchIdentity(ctx, acc, []string{
		"https://launchpad.net/~test1",
		"https://launchpad.net/~test2",
		"https://launchpad.net/~test3",
	})

	c.Check(err, qt.IsNil)
	c.Check(ids, qt.HasLen, 0)
}

func TestDefaultLaunchpadOpenID(t *testing.T) {
	c := qt.New(t)
	c.Check(ssoauthacl.DefaultLaunchpadOpenID(&ssoauth.Account{
		Provider: "login.ubuntu.com",
		OpenID:   "AAAAAAA",
	}), qt.Equals, "https://login.launchpad.net/+id/AAAAAAA")
	c.Check(ssoauthacl.DefaultLaunchpadOpenID(&ssoauth.Account{
		Provider: "login.launchpad.net",
		OpenID:   "BBBBBBB",
	}), qt.Equals, "https://login.launchpad.net/+id/BBBBBBB")
	c.Check(ssoauthacl.DefaultLaunchpadOpenID(&ssoauth.Account{
		Provider: "login.staging.ubuntu.com",
		OpenID:   "CCCCCCC",
	}), qt.Equals, "https://login-lp.staging.ubuntu.com/+id/CCCCCCC")
	c.Check(ssoauthacl.DefaultLaunchpadOpenID(&ssoauth.Account{
		Provider: "login-lp.staging.ubuntu.com",
		OpenID:   "DDDDDDD",
	}), qt.Equals, "https://login-lp.staging.ubuntu.com/+id/DDDDDDD")
}
