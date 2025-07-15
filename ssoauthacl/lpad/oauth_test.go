package lpad_test

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var _ = Suite(&OAuthS{})
var _ = Suite(&OAuthI{})

type OAuthS struct {
	HTTPSuite
}

type OAuthI struct {
	SuiteI
}

func (s *OAuthS) TestRequestToken(c *C) {
	gotAuthURL := ""
	callback := func(oauth *lpad.OAuth) error {
		gotAuthURL = oauth.AuthURL
		return errors.New("STOP!")
	}
	oauth := lpad.OAuth{
		Callback: callback,
	}

	testServer.PrepareResponse(200, nil, "oauth_token=mytoken&oauth_token_secret=mysecret")

	err := oauth.Login(testServer.URL)
	c.Assert(err, ErrorMatches, "STOP!")
	c.Assert(gotAuthURL, Equals, testServer.URL+"/+authorize-token?oauth_token=mytoken")
	c.Assert(oauth.BaseURL, Equals, testServer.URL)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/+request-token")
	c.Assert(req.Form["oauth_consumer_key"], DeepEquals, []string{"https://launchpad.net/lpad"})
	c.Assert(req.Form["oauth_signature_method"], DeepEquals, []string{"PLAINTEXT"})
	c.Assert(req.Form["oauth_signature"], DeepEquals, []string{"&"})

	c.Assert(oauth.Token, Equals, "mytoken")
	c.Assert(oauth.TokenSecret, Equals, "mysecret")
}

func (s *OAuthS) TestBaseURLStripping(c *C) {
	// https://api.launchpad.net/1.0/ as a BaseURL must
	// yield a https://launchpad.net/ BaseURL for auth.

	callback := func(oauth *lpad.OAuth) error {
		return errors.New("STOP!")
	}
	oauth := lpad.OAuth{
		Callback: callback,
	}

	testServer.PrepareResponse(200, nil, "oauth_token=mytoken&oauth_token_secret=mysecret")

	url_, err := url.Parse(testServer.URL)
	c.Assert(err, IsNil)

	url_.Host = "api." + url_.Host
	url_.Path = "/1.0/"

	c.Assert(url_.String(), Matches, `http://api\..*/1\.0/`)
	err = oauth.Login(url_.String())

	c.Assert(err, ErrorMatches, "STOP!")
	c.Assert(oauth.BaseURL, Equals, testServer.URL)
}

func (s *OAuthS) TestRequestTokenWithConsumer(c *C) {
	callback := func(oauth *lpad.OAuth) error {
		return errors.New("STOP!")
	}
	oauth := lpad.OAuth{
		Callback: callback,
		Consumer: "myconsumer",
	}

	testServer.PrepareResponse(200, nil, "oauth_token=mytoken&oauth_token_secret=mysecret")

	err := oauth.Login(testServer.URL)
	c.Assert(err, ErrorMatches, "STOP!")

	req := testServer.WaitRequest()
	c.Assert(req.Form["oauth_consumer_key"], DeepEquals, []string{"myconsumer"})
}

func (s *OAuthS) TestCallbackURL(c *C) {
	gotAuthURL := ""
	callback := func(oauth *lpad.OAuth) error {
		gotAuthURL = oauth.AuthURL
		return errors.New("STOP!")
	}
	oauth := lpad.OAuth{
		CallbackURL: "http://example.com",
		Callback:    callback,
	}

	testServer.PrepareResponse(200, nil, "oauth_token=mytoken&oauth_token_secret=mysecret")

	err := oauth.Login(testServer.URL)
	c.Assert(err, ErrorMatches, "STOP!")

	u, err := url.Parse(gotAuthURL)
	c.Assert(err, IsNil)
	c.Assert(u.Path, Equals, "/+authorize-token")

	q, err := url.ParseQuery(u.RawQuery)
	c.Assert(err, IsNil)
	c.Assert(q["oauth_token"], DeepEquals, []string{"mytoken"})
	c.Assert(q["oauth_callback"], DeepEquals, []string{"http://example.com"})
}

func (s *OAuthS) TestAccessToken(c *C) {
	testServer.PrepareResponse(200, nil, "oauth_token=mytoken1&oauth_token_secret=mysecret1")
	testServer.PrepareResponse(200, nil, "oauth_token=mytoken2&oauth_token_secret=mysecret2")

	oauth := lpad.OAuth{}
	err := oauth.Login(testServer.URL)
	c.Assert(err, IsNil)

	req1 := testServer.WaitRequest()
	c.Assert(req1.URL.Path, Equals, "/+request-token")

	req2 := testServer.WaitRequest()
	c.Assert(req2.Method, Equals, "POST")
	c.Assert(req2.URL.Path, Equals, "/+access-token")
	c.Assert(req2.Form["oauth_token"], DeepEquals, []string{"mytoken1"})
	c.Assert(req2.Form["oauth_signature"], DeepEquals, []string{"&mysecret1"})

	c.Assert(oauth.Token, Equals, "mytoken2")
	c.Assert(oauth.TokenSecret, Equals, "mysecret2")
	c.Assert(oauth.AuthURL, Equals, "")
}

func (s *OAuthS) TestSign(c *C) {
	oauth := lpad.OAuth{
		Token:       "my token",
		TokenSecret: "my secret",
	}

	req, err := http.NewRequest("GET", "http://example.com/path", nil)
	c.Assert(err, IsNil)

	err = oauth.Sign(req)
	c.Assert(err, IsNil)

	auth := req.Header.Get("Authorization")
	parts := strings.Split(auth, ", ")
	c.Assert(parts[0], Equals, `OAuth realm="https://api.launchpad.net/"`)
	c.Assert(parts[1], Equals, `oauth_consumer_key="https%3A%2F%2Flaunchpad.net%2Flpad"`)
	c.Assert(parts[2], Equals, `oauth_token="my+token"`)
	c.Assert(parts[3], Equals, `oauth_signature_method="PLAINTEXT"`)
	c.Assert(parts[4], Equals, `oauth_signature="%26my+secret"`)
	c.Assert(parts[5], Matches, `oauth_timestamp="[0-9]+"`)
	c.Assert(parts[6], Matches, `oauth_nonce="[0-9]+"`)
	c.Assert(parts[7], Equals, `oauth_version="1.0"`)
}

func (s *OAuthS) TestSignWithConsumer(c *C) {
	oauth := lpad.OAuth{
		Token:       "my token",
		TokenSecret: "my secret",
		Consumer:    "my consumer",
	}

	req, err := http.NewRequest("GET", "http://example.com/path", nil)
	c.Assert(err, IsNil)

	err = oauth.Sign(req)
	c.Assert(err, IsNil)

	auth := req.Header.Get("Authorization")
	c.Assert(auth, Matches, `.* oauth_consumer_key="my\+consumer".*`)
}

func (s *OAuthS) TestSignWithAnonymous(c *C) {
	oauth := lpad.OAuth{
		Consumer:  "my consumer",
		Anonymous: true,
	}

	req, err := http.NewRequest("GET", "http://example.com/path", nil)
	c.Assert(err, IsNil)

	err = oauth.Sign(req)
	c.Assert(err, IsNil)

	auth := req.Header.Get("Authorization")
	c.Assert(auth, Matches, `.* oauth_consumer_key="my\+consumer".*`)
	c.Assert(auth, Matches, `.* oauth_token="".*`)
	c.Assert(auth, Matches, `.* oauth_signature="%26".*`)
}

func (s *OAuthS) TestSignError(c *C) {
	err := (&lpad.OAuth{}).Sign(nil)
	c.Assert(err, ErrorMatches, `OAuth can't Sign without a token \(missing Login\?\)`)
	err = (&lpad.OAuth{Token: "mytoken"}).Sign(nil)
	c.Assert(err, ErrorMatches, `OAuth can't Sign without a token secret \(missing Login\?\)`)
}

func (s *OAuthS) TestDontLoginWithExistingSecret(c *C) {
	callback := func(oauth *lpad.OAuth) error {
		c.Error("Callback called!")
		return errors.New("STOP!")
	}
	oauth := lpad.OAuth{
		Token:       "initialtoken",
		TokenSecret: "initialsecret",
		Callback:    callback,
	}
	err := oauth.Login(testServer.URL)
	c.Assert(err, IsNil)
}

func (s *OAuthS) TestDontLoginWithAnonymous(c *C) {
	callback := func(oauth *lpad.OAuth) error {
		c.Error("Callback called!")
		return errors.New("STOP!")
	}
	oauth := lpad.OAuth{
		Anonymous: true,
		Callback:  callback,
	}
	err := oauth.Login(testServer.URL)
	c.Assert(err, IsNil)
}

func fakeHome(c *C) (dir string, restore func()) {
	realHome := os.Getenv("HOME")
	fakeHome := c.MkDir()
	restore = func() {
		os.Setenv("HOME", realHome)
	}
	os.Setenv("HOME", fakeHome)
	return fakeHome, restore
}

func (s *OAuthS) TestStoredOAuthLoginWithStored(c *C) {
	home, restore := fakeHome(c)
	defer restore()

	file, err := os.Create(filepath.Join(home, ".lpad_oauth"))
	c.Assert(err, IsNil)
	data, err := json.Marshal(M{"Token": "mytoken", "TokenSecret": "mysecret"})
	c.Assert(err, IsNil)
	file.Write(data)
	file.Close()

	oauth := lpad.StoredOAuth{}
	oauth.Login("baseURL")

	c.Assert(oauth.Token, Equals, "mytoken")
	c.Assert(oauth.TokenSecret, Equals, "mysecret")
}

func (s *OAuthS) TestStoredOAuthLogin(c *C) {
	home, restore := fakeHome(c)
	defer restore()

	testServer.PrepareResponse(200, nil, "oauth_token=mytoken1&oauth_token_secret=mysecret1")
	testServer.PrepareResponse(200, nil, "oauth_token=mytoken2&oauth_token_secret=mysecret2")

	oauth := lpad.StoredOAuth{}
	err := oauth.Login(testServer.URL)
	c.Assert(err, IsNil)

	req1 := testServer.WaitRequest()
	c.Assert(req1.URL.Path, Equals, "/+request-token")

	req2 := testServer.WaitRequest()
	c.Assert(req2.Method, Equals, "POST")
	c.Assert(req2.URL.Path, Equals, "/+access-token")

	c.Assert(oauth.Token, Equals, "mytoken2")
	c.Assert(oauth.TokenSecret, Equals, "mysecret2")
	c.Assert(oauth.AuthURL, Equals, "")

	data, err := ioutil.ReadFile(filepath.Join(home, ".lpad_oauth"))
	c.Assert(err, IsNil)

	result := lpad.OAuth{}
	err = json.Unmarshal(data, &result)
	c.Assert(err, IsNil)
	c.Assert(result.Token, Equals, "mytoken2")
	c.Assert(result.TokenSecret, Equals, "mysecret2")
}

func (s *OAuthS) TestStoredOAuthSignForwards(c *C) {
	err := (&lpad.StoredOAuth{}).Sign(nil)
	c.Assert(err, ErrorMatches, `OAuth can't Sign without a token \(missing Login\?\)`)
}
