package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
	"time"
)

func (s *ModelS) TestDistro(c *C) {
	m := M{
		"name":                "thename",
		"display_name":        "Display Name",
		"title":               "Title",
		"summary":             "Summary",
		"description":         "Description",
		"web_link":            "http://page",
		"current_series_link": testServer.URL + "/focus_link",
	}
	distro := &lpad.Distro{lpad.NewValue(nil, "", "", m)}
	c.Assert(distro.Name(), Equals, "thename")
	c.Assert(distro.DisplayName(), Equals, "Display Name")
	c.Assert(distro.Title(), Equals, "Title")
	c.Assert(distro.Summary(), Equals, "Summary")
	c.Assert(distro.Description(), Equals, "Description")
	c.Assert(distro.WebPage(), Equals, "http://page")

	distro.SetName("newname")
	distro.SetDisplayName("New Display Name")
	distro.SetTitle("New Title")
	distro.SetSummary("New summary")
	distro.SetDescription("New description")
	c.Assert(distro.Name(), Equals, "newname")
	c.Assert(distro.DisplayName(), Equals, "New Display Name")
	c.Assert(distro.Title(), Equals, "New Title")
	c.Assert(distro.Summary(), Equals, "New summary")
	c.Assert(distro.Description(), Equals, "New description")

	testServer.PrepareResponse(200, jsonType, `{"name": "seriesname"}`)
	series, err := distro.FocusSeries()
	c.Assert(err, IsNil)
	c.Assert(series.Name(), Equals, "seriesname")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/focus_link")
}

func (s *ModelS) TestDistroSeries(c *C) {
	m := M{
		"name":           "thename",
		"displayname":    "Display Name",
		"fullseriesname": "Full Series Name",
		"title":          "Title",
		"summary":        "Summary",
		"description":    "Description",
		"active":         true,
		"web_link":       "http://page",
	}

	series := &lpad.DistroSeries{lpad.NewValue(nil, "", "", m)}
	c.Assert(series.Name(), Equals, "thename")
	c.Assert(series.DisplayName(), Equals, "Display Name")
	c.Assert(series.FullSeriesName(), Equals, "Full Series Name")
	c.Assert(series.Title(), Equals, "Title")
	c.Assert(series.Summary(), Equals, "Summary")
	c.Assert(series.Description(), Equals, "Description")
	c.Assert(series.Active(), Equals, true)
	c.Assert(series.WebPage(), Equals, "http://page")

	series.SetName("newname")
	series.SetTitle("New Title")
	series.SetSummary("New summary")
	series.SetActive(false)
	c.Assert(series.Name(), Equals, "newname")
	c.Assert(series.Title(), Equals, "New Title")
	c.Assert(series.Summary(), Equals, "New summary")
	c.Assert(series.Active(), Equals, false)
}

func (s *ModelS) TestRootDistro(c *C) {
	data := `{
		"name": "Name",
		"title": "Title",
		"description": "Description"
	}`
	testServer.PrepareResponse(200, jsonType, data)
	root := lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}
	distro, err := root.Distro("myproj")
	c.Assert(err, IsNil)
	c.Assert(distro.Name(), Equals, "Name")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myproj")
}

func (s *ModelS) TestDistroActiveMilestones(c *C) {
	data := `{
		"total_size": 2,
		"start": 0,
		"entries": [{
			"self_link": "http://self0",
			"name": "Name0"
		}, {
			"self_link": "http://self1",
			"name": "Name1"
		}]
	}`
	testServer.PrepareResponse(200, jsonType, data)
	m := M{
		"active_milestones_collection_link": testServer.URL + "/col_link",
	}
	distro := lpad.Distro{lpad.NewValue(nil, testServer.URL, "", m)}
	list, err := distro.ActiveMilestones()
	c.Assert(err, IsNil)
	c.Assert(list.TotalSize(), Equals, 2)

	names := []string{}
	list.For(func(ms *lpad.Milestone) error {
		names = append(names, ms.Name())
		return nil
	})
	c.Assert(names, DeepEquals, []string{"Name0", "Name1"})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/col_link")
}

func (s *ModelS) TestDistroAllSeries(c *C) {
	data := `{
		"total_size": 2,
		"start": 0,
		"entries": [{
			"self_link": "http://self0",
			"name": "Name0"
		}, {
			"self_link": "http://self1",
			"name": "Name1"
		}]
	}`
	testServer.PrepareResponse(200, jsonType, data)
	m := M{
		"series_collection_link": testServer.URL + "/col_link",
	}
	distro := lpad.Distro{lpad.NewValue(nil, testServer.URL, "", m)}
	list, err := distro.AllSeries()
	c.Assert(err, IsNil)
	c.Assert(list.TotalSize(), Equals, 2)

	names := []string{}
	list.For(func(s *lpad.DistroSeries) error {
		names = append(names, s.Name())
		return nil
	})
	c.Assert(names, DeepEquals, []string{"Name0", "Name1"})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/col_link")
}

func (s *ModelS) TestBranchTips(c *C) {
	data := `[["lp:a", "rev1", ["series1", "series2"]], ["lp:b", "rev2", []]]`
	testServer.PrepareResponse(200, jsonType, data)
	distro := lpad.Distro{lpad.NewValue(nil, testServer.URL, testServer.URL+"/distro", nil)}
	tips, err := distro.BranchTips(time.Time{})
	c.Assert(err, IsNil)
	c.Assert(tips, DeepEquals, []lpad.BranchTip{
		{"lp:a", "rev1", []string{"series1", "series2"}},
		{"lp:b", "rev2", []string{}},
	})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/distro")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"getBranchTips"})
	c.Assert(req.Form["since"], DeepEquals, []string(nil))
}

func (s *ModelS) TestBranchTipsWithSince(c *C) {
	testServer.PrepareResponse(200, jsonType, "[]")
	distro := lpad.Distro{lpad.NewValue(nil, testServer.URL, testServer.URL+"/distro", nil)}
	tips, err := distro.BranchTips(time.Unix(1316567786, 0))
	c.Assert(err, IsNil)
	c.Assert(tips, DeepEquals, []lpad.BranchTip(nil))

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/distro")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"getBranchTips"})
	c.Assert(req.Form["since"], DeepEquals, []string{"2011-09-21T01:16:26Z"})
}
