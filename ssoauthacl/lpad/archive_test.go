package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
)

func (s *ModelS) TestArchive(c *C) {
	m := M{
		"name":              "thename",
		"displayname":       "The Name",
		"description":       "The Description",
		"web_link":          "http://page",
		"distribution_link": testServer.URL + "/distribution_link",
	}
	archive := &lpad.Archive{lpad.NewValue(nil, "", "", m)}
	c.Assert(archive.Name(), Equals, "thename")
	c.Assert(archive.DisplayName(), Equals, "The Name")
	c.Assert(archive.Description(), Equals, "The Description")
	c.Assert(archive.WebPage(), Equals, "http://page")

	testServer.PrepareResponse(200, jsonType, `{"name": "distroname"}`)
	distro, err := archive.Distro()
	c.Assert(err, IsNil)
	c.Assert(distro.Name(), Equals, "distroname")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/distribution_link")
}

func (s *ModelS) TestArchivePublication(c *C) {
	data := `{ "total_size": 2,
		"start": 0,
		"entries": [
            {"source_package_name": "whatever", "source_package_version": "1.0" },
            {"source_package_name": "whatever", "source_package_version": "1.1" }
            ]
        }`

	testServer.PrepareResponse(200, jsonType, data)
	archive := &lpad.Archive{lpad.NewValue(nil, testServer.URL, testServer.URL+"/archive", nil)}
	phlist, err := archive.Publication("whatever", "Published")
	c.Assert(err, IsNil)
	phlist.For(func(ph *lpad.Publication) error {
		c.Assert(ph.PackageName(), Equals, "whatever")
		return nil
	})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/archive")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"getPublishedSources"})
	c.Assert(req.Form["source_name"], DeepEquals, []string{"whatever"})
}
