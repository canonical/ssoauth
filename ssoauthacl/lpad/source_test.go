package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
)

func (s *ModelS) TestSourcePackage(c *C) {
	m := M{
		"name":                            "thename",
		"displayname":                     "Display Name",
		"latest_published_component_name": "universe",
		"web_link":                        "http://page",
		"self_link":                       "http://selfpage",
		"distribution_link":               testServer.URL + "/distribution_link",
		"distroseries_link":               testServer.URL + "/distroseries_link",
	}
	source := &lpad.SourcePackage{lpad.NewValue(nil, "", "", m)}
	c.Assert(source.Name(), Equals, "thename")
	c.Assert(source.DisplayName(), Equals, "Display Name")
	c.Assert(source.LatestComponent(), Equals, "universe")
	c.Assert(source.WebPage(), Equals, "http://page")

	testServer.PrepareResponse(200, jsonType, `{"name": "distroname"}`)
	distro, err := source.Distro()
	c.Assert(err, IsNil)
	c.Assert(distro.Name(), Equals, "distroname")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/distribution_link")

	testServer.PrepareResponse(200, jsonType, `{"name": "seriesname"}`)
	series, err := source.DistroSeries()
	c.Assert(err, IsNil)
	c.Assert(series.Name(), Equals, "seriesname")

	req = testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/distroseries_link")
}

func (s *ModelS) TestDistroSourcePackage(c *C) {
	m := M{
		"name":                            "thename",
		"display_name":                     "Display Name",
		"title": "title",
		"web_link":                        "http://page",
		"self_link":                       "http://selfpage",
		"distribution_link":               testServer.URL + "/distribution_link",
	}
	source := &lpad.DistroSourcePackage{lpad.NewValue(nil, "", "", m)}
	c.Assert(source.Name(), Equals, "thename")
	c.Assert(source.DisplayName(), Equals, "Display Name")
	c.Assert(source.Title(), Equals, "title")
	c.Assert(source.WebPage(), Equals, "http://page")

	testServer.PrepareResponse(200, jsonType, `{"name": "distroname"}`)
	distro, err := source.Distro()
	c.Assert(err, IsNil)
	c.Assert(distro.Name(), Equals, "distroname")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/distribution_link")
}
