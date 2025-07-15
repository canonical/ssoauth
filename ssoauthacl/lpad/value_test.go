package lpad_test

import (
	"encoding/json"
	"errors"
	"fmt"
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
	"net/url"
	"strconv"
)

var _ = Suite(&ValueS{})
var _ = Suite(&ValueI{})

type ValueS struct {
	HTTPSuite
}

type ValueI struct {
	SuiteI
}

var jsonType = map[string]string{
	"Content-Type": "application/json",
}

func (s *ValueS) TestIsValid(c *C) {
	var v *lpad.Value
	c.Assert(v.IsValid(), Equals, false)
	v = lpad.NewValue(nil, "", "", nil)
	c.Assert(v.IsValid(), Equals, true)
}

func (s *ValueS) TestMapInit(c *C) {
	v := lpad.NewValue(nil, "", "", nil)
	m := v.Map()
	c.Assert(m, NotNil)
	m["a"] = 1
	c.Assert(v.Map()["a"], Equals, 1)
}

func (s *ValueS) TestFieldMethods(c *C) {
	m := M{
		"n": nil,
		"s": "string",
		"f": 42.1,
		"b": true,
		"l": []interface{}{"1", "2", 3},
	}
	v := lpad.NewValue(nil, "", "", m)
	c.Assert(v.StringField("s"), Equals, "string")
	c.Assert(v.StringField("n"), Equals, "")
	c.Assert(v.StringField("x"), Equals, "")
	c.Assert(v.IntField("f"), Equals, 42)
	c.Assert(v.IntField("n"), Equals, 0)
	c.Assert(v.IntField("x"), Equals, 0)
	c.Assert(v.FloatField("f"), Equals, 42.1)
	c.Assert(v.FloatField("n"), Equals, 0.0)
	c.Assert(v.FloatField("x"), Equals, 0.0)
	c.Assert(v.BoolField("b"), Equals, true)
	c.Assert(v.BoolField("n"), Equals, false)
	c.Assert(v.BoolField("x"), Equals, false)
	c.Assert(v.StringListField("l"), DeepEquals, []string{"1", "2"})
}

func (s *ValueS) TestGet(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"a": 1, "b": [1, 2]}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	o, err := v.Get(nil)
	c.Assert(err, IsNil)
	c.Assert(&o, DeepEquals, &v)
	c.Assert(v.Map()["a"], Equals, float64(1))
	c.Assert(v.Map()["b"], DeepEquals, []interface{}{float64(1), float64(2)})
	c.Assert(v.AbsLoc(), Equals, testServer.URL+"/myvalue")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myvalue")
	c.Assert(req.Header.Get("Accept"), Equals, "application/json")
}

func (s *ValueS) TestGetNull(c *C) {
	// In certain cases, like branch's getByUrl ws.op, Launchpad returns
	// 200 + null for what is actually a not found object.
	testServer.PrepareResponse(200, jsonType, "null")
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	o, err := v.Get(nil)
	c.Assert(err, Equals, lpad.ErrNotFound)
	c.Assert(o, IsNil)
}

func (s *ValueS) TestGetList(c *C) {
	testServer.PrepareResponse(200, jsonType, `["a", "b", "c"]`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(nil)
	c.Assert(err, IsNil)
	c.Assert(v.Map()["value"], DeepEquals, []interface{}{"a", "b", "c"})
}

func (s *ValueS) TestGetAbsLoc(c *C) {
	data := `{"a": 1, "self_link": "` + testServer.URL + `/self_link"}`
	testServer.PrepareResponse(200, jsonType, data)
	testServer.PrepareResponse(200, jsonType, data)

	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(nil)
	c.Assert(err, IsNil)
	c.Assert(v.AbsLoc(), Equals, testServer.URL+"/self_link")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myvalue")

	_, err = v.Get(nil)
	c.Assert(err, IsNil)
	c.Assert(v.AbsLoc(), Equals, testServer.URL+"/self_link")

	req = testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/self_link")
}

func (s *ValueS) TestGetWithParams(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(lpad.Params{"k": "v"})
	c.Assert(err, IsNil)
	c.Assert(v.AbsLoc(), Equals, testServer.URL+"/myvalue")
	c.Assert(v.Map()["ok"], Equals, true)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myvalue")
	c.Assert(req.URL.RawQuery, Equals, "k=v")
}

func (s *ValueS) TestGetWithParamsMerging(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue?k2=v2", nil)
	_, err := v.Get(lpad.Params{"k1": "v1"})
	c.Assert(err, IsNil)
	c.Assert(v.Map()["ok"], Equals, true)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myvalue")
	params, err := url.ParseQuery(req.URL.RawQuery)
	c.Assert(err, IsNil)
	c.Assert(params["k1"], DeepEquals, []string{"v1"})
	c.Assert(params["k2"], DeepEquals, []string{"v2"})
}

func (s *ValueS) TestGetSign(c *C) {
	oauth := &lpad.OAuth{Token: "mytoken", TokenSecret: "mytokensecret"}
	session := lpad.NewSession(oauth)

	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)
	v := lpad.NewValue(session, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(nil)
	c.Assert(err, IsNil)
	c.Assert(v.Map()["ok"], Equals, true)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myvalue")
	c.Assert(req.Header["Authorization"], NotNil)
	c.Assert(req.Header["Authorization"][0], Matches, "OAuth.*")
}

func (s *ValueS) TestGetRedirect(c *C) {
	headers := map[string]string{
		"Location": testServer.URL + "/myothervalue",
	}
	testServer.PrepareResponse(303, headers, "")
	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(nil)
	c.Assert(err, IsNil)
	c.Assert(v.AbsLoc(), Equals, testServer.URL+"/myothervalue")
	c.Assert(v.Map()["ok"], Equals, true)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myvalue")
}

func (s *ValueS) TestGetRedirectWithParams(c *C) {
	headers := map[string]string{
		"Location": testServer.URL + "/myothervalue?p=1",
	}
	testServer.PrepareResponse(303, headers, "")
	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(lpad.Params{"k": "v"})
	c.Assert(err, IsNil)
	c.Assert(v.AbsLoc(), Equals, testServer.URL+"/myothervalue?p=1")
	c.Assert(v.Map()["ok"], Equals, true)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myvalue")
	c.Assert(req.Form.Get("k"), Equals, "v")

	req = testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myothervalue")
	c.Assert(req.Form.Get("k"), Equals, "")
}

func (s *ValueS) TestGetNonJSONContent(c *C) {
	headers := map[string]string{
		"Content-Type": "text/plain",
	}
	testServer.PrepareResponse(200, headers, "NOT JSON")
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(nil)
	c.Assert(err, ErrorMatches, "Non-JSON content-type: text/plain.*")
}

func (s *ValueS) TestGetError(c *C) {
	testServer.PrepareResponse(500, jsonType, `{"what": "ever"}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(nil)
	c.Assert(err, ErrorMatches, `Server returned 500 and body: {"what": "ever"}`)

	testServer.PrepareResponse(500, jsonType, "")
	v = lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err = v.Get(nil)
	c.Assert(err, ErrorMatches, `Server returned 500 and no body.`)

	testServer.PrepareResponse(404, jsonType, "")
	v = lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err = v.Get(nil)
	c.Assert(err, Equals, lpad.ErrNotFound)
}

func (s *ValueS) TestGetRedirectWithoutLocation(c *C) {
	headers := map[string]string{
		"Content-Type": "application/json", // Should be ignored.
	}
	testServer.PrepareResponse(303, headers, `{"ok": true}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(nil)
	c.Assert(err, ErrorMatches, "Get : 303 response missing Location header")
}

func (s *ValueS) TestPost(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	other, err := v.Post(nil)
	c.Assert(err, IsNil)
	c.Assert(v.Map(), DeepEquals, map[string]interface{}{})
	c.Assert(other.Map()["ok"], Equals, true)
	c.Assert(other.AbsLoc(), Equals, v.AbsLoc())

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/myvalue")
}

func (s *ValueS) TestPostWithParams(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"ok": true, "self_link": "/self"}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	other, err := v.Post(lpad.Params{"k": "v"})
	c.Assert(err, IsNil)
	c.Assert(other.AbsLoc(), Equals, "/self")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/myvalue")
	c.Assert(req.Form["k"], DeepEquals, []string{"v"})
}

func (s *ValueS) TestPostWithSelfLinkOnOriginal(c *C) {
	m := M{"self_link": testServer.URL+"/self"}
	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)
	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", m)
	other, err := v.Post(lpad.Params{"k": "v"})
	c.Assert(err, IsNil)
	c.Assert(other.AbsLoc(), Equals, testServer.URL+"/self")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/self")
	c.Assert(req.Form["k"], DeepEquals, []string{"v"})
}

func (s *ValueS) TestPostCreation(c *C) {
	headers := map[string]string{
		"Location":     testServer.URL + "/newvalue",
		"Content-Type": "application/json", // Should be ignored.
	}
	testServer.PrepareResponse(201, headers, `{"ok": false}`)
	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)

	v := lpad.NewValue(nil, testServer.URL, testServer.URL+"/myvalue", nil)
	other, err := v.Post(nil)
	c.Assert(err, IsNil)
	c.Assert(len(v.Map()), Equals, 0)
	c.Assert(other.BaseLoc(), Equals, testServer.URL)
	c.Assert(other.AbsLoc(), Equals, testServer.URL+"/newvalue")
	c.Assert(other.Map()["ok"], Equals, true)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/myvalue")

	req = testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/newvalue")
	c.Assert(len(req.Form), Equals, 0)
}

func (s *ValueS) TestPostSign(c *C) {
	oauth := &lpad.OAuth{Token: "mytoken", TokenSecret: "mytokensecret"}
	session := lpad.NewSession(oauth)

	testServer.PrepareResponse(200, jsonType, `{"ok": true}`)
	v := lpad.NewValue(session, "", testServer.URL+"/myvalue", nil)
	other, err := v.Post(nil)
	c.Assert(err, IsNil)
	c.Assert(len(v.Map()), Equals, 0)
	c.Assert(other.Map()["ok"], Equals, true)
	c.Assert(other.AbsLoc(), Equals, v.AbsLoc())
	c.Assert(other.Session(), Equals, v.Session())

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/myvalue")
	c.Assert(req.Header["Authorization"], NotNil)
	c.Assert(req.Header["Authorization"][0], Matches, "OAuth.*")
}

func (s *ValueS) TestPatch(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"a": 1, "b": 2}`)
	testServer.PrepareResponse(200, nil, "")

	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(nil)
	c.Assert(err, IsNil)

	v.SetField("a", 3)
	v.SetField("c", "string")
	v.SetField("d", true)
	v.SetField("e", []string{"a", "b"})
	c.Assert(v.Map()["a"], Equals, 3.0)
	c.Assert(v.Map()["b"], Equals, 2.0)
	c.Assert(v.Map()["c"], Equals, "string")
	c.Assert(v.Map()["d"], Equals, true)
	c.Assert(v.Map()["e"], DeepEquals, []interface{}{"a", "b"})

	err = v.Patch()
	c.Assert(err, IsNil)

	req1 := testServer.WaitRequest()
	c.Assert(req1.Method, Equals, "GET")
	c.Assert(req1.URL.Path, Equals, "/myvalue")

	req2 := testServer.WaitRequest()
	c.Assert(req2.Method, Equals, "PATCH")
	c.Assert(req2.URL.Path, Equals, "/myvalue")
	c.Assert(req2.Header.Get("Accept"), Equals, "application/json")
	c.Assert(req2.Header.Get("Content-Type"), Equals, "application/json")

	var m M
	err = json.Unmarshal([]byte(body(req2)), &m)
	c.Assert(err, IsNil)
	c.Assert(m, DeepEquals, M{"a": 3.0, "c": "string", "d": true, "e": []interface{}{"a", "b"}})
}

func (s *ValueS) TestPatchWithContent(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"a": 1, "b": 2}`)
	testServer.PrepareResponse(209, jsonType, `{"new": "content"}`)

	v := lpad.NewValue(nil, "", testServer.URL+"/myvalue", nil)
	_, err := v.Get(nil)
	c.Assert(err, IsNil)

	v.SetField("a", 3)

	err = v.Patch()
	c.Assert(err, IsNil)
	c.Assert(v.Map(), DeepEquals, map[string]interface{}{"new": "content"})

	req1 := testServer.WaitRequest()
	c.Assert(req1.Method, Equals, "GET")
	c.Assert(req1.URL.Path, Equals, "/myvalue")

	req2 := testServer.WaitRequest()
	c.Assert(req2.Method, Equals, "PATCH")
	c.Assert(req2.URL.Path, Equals, "/myvalue")
	c.Assert(req2.Header.Get("Accept"), Equals, "application/json")
	c.Assert(req2.Header.Get("Content-Type"), Equals, "application/json")

	var m M
	err = json.Unmarshal([]byte(body(req2)), &m)
	c.Assert(err, IsNil)
	c.Assert(m, DeepEquals, M{"a": 3.0})
}

type locationTest struct {
	BaseLoc, Loc, RelLoc, AbsLoc string
}

var locationTests = []locationTest{
	{"http://e.c/base/", "http://e.c/base/more/foo", "bar", "http://e.c/base/more/foo/bar"},
	{"http://e.c/base/", "http://e.c/base/more/foo", "../bar", "http://e.c/base/more/bar"},
	{"http://e.c/base/", "http://e.c/base/more/foo", "/bar", "http://e.c/base/bar"},
	{"http://e.c/base", "http://e.c/base/more/foo", "/bar", "http://e.c/base/bar"},
}

func (s *ValueS) TestLocation(c *C) {
	oauth := &lpad.OAuth{Token: "mytoken", TokenSecret: "mytokensecret"}
	session := lpad.NewSession(oauth)

	for _, test := range locationTests {
		r1 := lpad.NewValue(session, test.BaseLoc, test.Loc, nil)
		r2 := r1.Location(test.RelLoc)
		c.Assert(r2.AbsLoc(), Equals, test.AbsLoc)
		c.Assert(r2.BaseLoc(), Equals, test.BaseLoc)
		c.Assert(r2.Session(), Equals, session)
	}
}

func (s *ValueS) TestLink(c *C) {
	oauth := &lpad.OAuth{Token: "mytoken", TokenSecret: "mytokensecret"}
	session := lpad.NewSession(oauth)

	for _, test := range locationTests {
		m := map[string]interface{}{"some_link": test.AbsLoc}
		v1 := lpad.NewValue(session, test.BaseLoc, test.Loc, m)
		v2 := v1.Link("some_link")
		c.Assert(v2, NotNil)
		c.Assert(v2.AbsLoc(), Equals, test.AbsLoc)
		c.Assert(v2.BaseLoc(), Equals, test.BaseLoc)
		c.Assert(v2.Session(), Equals, session)

		v3 := v1.Link("bad_link")
		c.Assert(v3, IsNil)
	}
}

func (s *ValueS) TestNilValueHandlign(c *C) {
	// This is meaningful so Link can return a single
	// value and be used as Link("link").Get(nil), etc.
	nv := (*lpad.Value)(nil)

	v, err := nv.Get(nil)
	c.Assert(v, IsNil)
	c.Assert(err, Equals, lpad.ErrNotFound)

	v, err = nv.Post(nil)
	c.Assert(v, IsNil)
	c.Assert(err, Equals, lpad.ErrNotFound)

	err = nv.Patch()
	c.Assert(err, Equals, lpad.ErrNotFound)
}

func (s *ValueS) TestCollection(c *C) {
	data0 := `{
		"total_size": 5,
		"start": 1,
		"next_collection_link": "%s",
		"entries": [{"self_link": "http://self1"}, {"self_link": "http://self2"}]
	}`
	data1 := `{
		"total_size": 5,
		"start": 3,
		"entries": [{"self_link": "http://self3"}, {"self_link": "http://self4"}]
	}`
	testServer.PrepareResponse(200, jsonType, fmt.Sprintf(data0, testServer.URL+"/next?n=10"))
	testServer.PrepareResponse(200, jsonType, data1)

	v := lpad.NewValue(nil, "", testServer.URL+"/mycol", nil)

	_, err := v.Get(nil)
	c.Assert(err, IsNil)

	c.Assert(v.TotalSize(), Equals, 5)
	c.Assert(v.StartIndex(), Equals, 1)

	i := 1
	err = v.For(func(v *lpad.Value) error {
		c.Assert(v.Map()["self_link"], Equals, "http://self"+strconv.Itoa(i))
		i++
		return nil
	})
	c.Assert(err, IsNil)
	c.Assert(i, Equals, 5)

	testServer.WaitRequest()
	req1 := testServer.WaitRequest()
	c.Assert(req1.Form["n"], DeepEquals, []string{"10"})
}

func (s *ValueS) TestCollectionGetError(c *C) {
	data := `{
		"total_size": 2,
		"start": 0,
		"next_collection_link": "%s",
		"entries": [{"self_link": "http://self1"}]
	}`
	testServer.PrepareResponse(200, jsonType, fmt.Sprintf(data, testServer.URL+"/next"))
	testServer.PrepareResponse(500, jsonType, "")

	v := lpad.NewValue(nil, "", testServer.URL+"/mycol", nil)

	_, err := v.Get(nil)
	c.Assert(err, IsNil)

	i := 0
	err = v.For(func(v *lpad.Value) error {
		i++
		return nil
	})
	c.Assert(err, ErrorMatches, ".* returned 500 .*")
	c.Assert(i, Equals, 1)
}

func (s *ValueS) TestCollectionNoEntries(c *C) {
	data := `{"total_size": 2, "start": 0}`
	testServer.PrepareResponse(200, jsonType, data)
	v := lpad.NewValue(nil, "", testServer.URL+"/mycol", nil)

	_, err := v.Get(nil)
	c.Assert(err, IsNil)

	i := 0
	err = v.For(func(v *lpad.Value) error {
		i++
		return nil
	})
	c.Assert(err, ErrorMatches, "No entries found in value")
	c.Assert(i, Equals, 0)
}

func (s *ValueS) TestCollectionIterError(c *C) {
	data := `{
		"total_size": 2,
		"start": 0,
		"entries": [{"self_link": "http://self1"}, {"self_link": "http://self2"}]
	}`
	testServer.PrepareResponse(200, jsonType, data)
	v := lpad.NewValue(nil, "", testServer.URL+"/mycol", nil)

	_, err := v.Get(nil)
	c.Assert(err, IsNil)

	i := 0
	err = v.For(func(v *lpad.Value) error {
		i++
		return errors.New("Stop!")
	})
	c.Assert(err, ErrorMatches, "Stop!")
	c.Assert(i, Equals, 1)
}
