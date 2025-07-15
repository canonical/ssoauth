package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
	"net/http"
)

var _ = Suite(&SessionS{})
var _ = Suite(&SessionI{})

type SessionS struct {
	HTTPSuite
}

type SessionI struct {
	SuiteI
}

type dummyAuth struct {
	loginBaseURL string
	loginErr     error
	signReq      *http.Request
	signErr      error
}

func (a *dummyAuth) Login(baseURL string) error {
	a.loginBaseURL = baseURL
	return a.loginErr
}

func (a *dummyAuth) Sign(r *http.Request) error {
	a.signReq = r
	return a.signErr
}

func (s *SessionS) TestLogin(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)

	auth := &dummyAuth{}
	root, err := lpad.Login(lpad.APIBase(testServer.URL), auth)
	c.Assert(err, IsNil)
	c.Assert(auth.loginBaseURL, Equals, testServer.URL)

	c.Assert(root.BaseLoc(), Equals, testServer.URL)
	c.Assert(root.AbsLoc(), Equals, testServer.URL)
	c.Assert(len(root.Map()), Equals, 0)

	_, err = root.Get(nil)
	c.Assert(err, IsNil)
	c.Assert(root.Map()["ok"], Equals, true)

	c.Assert(auth.signReq, NotNil)
	c.Assert(auth.signReq.URL.String(), Equals, testServer.URL)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/")
}

var lpadAuth = &lpad.OAuth{
	Token:       "SfVJpl7pJgSLJX9cm0wj",
	TokenSecret: "CXJGg1t5gTdjDqtFG0HNBFQn8WLWq8QQ3B2sHh9NmgLxQ6kGl9m123gQLZpDF8HFxQzk8HV78c9sGHQb",
}

func (s *SessionI) TestLogin(c *C) {
	root, err := lpad.Login(lpad.Production, lpadAuth)
	me, err := root.Me()
	c.Assert(err, IsNil)
	c.Assert(me.DisplayName(), Equals, "Lpad Test User")
}
