package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
)

func (s *ModelS) TestBuild(c *C) {
	m := M{
		"title":                           "thetitle",
		"arch_tag":                        "armel",
		"buildstate":                      "Failed to build",
		"build_log_url":                   "http://logurl",
		"upload_log_url":                  "http://uploadurl",
		"web_link":                        "http://page",
		"datecreated":                     "2011-10-10T00:00:00",
		"datebuilt":                       "2011-10-10T00:00:10",
		"current_source_publication_link": testServer.URL + "/pub_link",
	}
	build := &lpad.Build{lpad.NewValue(nil, "", "", m)}
	c.Assert(build.Title(), Equals, "thetitle")
	c.Assert(build.Arch(), Equals, "armel")
	c.Assert(build.State(), Equals, lpad.BuildState("Failed to build"))
	c.Assert(build.BuildLogURL(), Equals, "http://logurl")
	c.Assert(build.UploadLogURL(), Equals, "http://uploadurl")
	c.Assert(build.WebPage(), Equals, "http://page")
	c.Assert(build.Created(), Equals, "2011-10-10T00:00:00")
	c.Assert(build.Finished(), Equals, "2011-10-10T00:00:10")

	testServer.PrepareResponse(200, jsonType, `{"source_package_name": "packagename"}`)

	p, err := build.Publication()
	c.Assert(err, IsNil)
	c.Assert(p.PackageName(), Equals, "packagename")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/pub_link")
}

func (s *ModelS) TestBuildRetry(c *C) {
	testServer.PrepareResponse(200, jsonType, "{}")

	build := &lpad.Build{lpad.NewValue(nil, testServer.URL, testServer.URL + "/build", nil)}
	err := build.Retry()
	c.Assert(err, IsNil)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/build")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"retry"})
}

func (s *ModelS) TestPublication(c *C) {
	m := M{
		"source_package_name":    "pkgname",
		"source_package_version": "pkgversion",
		"component_name":         "main",
		"distro_series_link":     testServer.URL + "/distro_series_link",
		"archive_link":           testServer.URL + "/archive_link",
	}
	p := &lpad.Publication{lpad.NewValue(nil, "", "", m)}
	c.Assert(p.PackageName(), Equals, "pkgname")
	c.Assert(p.PackageVersion(), Equals, "pkgversion")
	c.Assert(p.Component(), Equals, "main")

	testServer.PrepareResponse(200, jsonType, `{"name": "archivename"}`)
	archive, err := p.Archive()
	c.Assert(err, IsNil)
	c.Assert(archive.Name(), Equals, "archivename")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/archive_link")

	testServer.PrepareResponse(200, jsonType, `{"name": "seriesname"}`)
	series, err := p.DistroSeries()
	c.Assert(err, IsNil)
	c.Assert(series.Name(), Equals, "seriesname")

	req = testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/distro_series_link")
}
