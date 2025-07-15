package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
)

func (s *ModelS) TestProject(c *C) {
	m := M{
		"name":                   "thename",
		"display_name":           "Display Name",
		"title":                  "Title",
		"summary":                "Summary",
		"description":            "Description",
		"web_link":               "http://page",
		"development_focus_link": testServer.URL + "/focus_link",
	}
	project := &lpad.Project{lpad.NewValue(nil, "", "", m)}
	c.Assert(project.Name(), Equals, "thename")
	c.Assert(project.DisplayName(), Equals, "Display Name")
	c.Assert(project.Title(), Equals, "Title")
	c.Assert(project.Summary(), Equals, "Summary")
	c.Assert(project.Description(), Equals, "Description")
	c.Assert(project.WebPage(), Equals, "http://page")
	project.SetName("newname")
	project.SetDisplayName("New Display Name")
	project.SetTitle("New Title")
	project.SetSummary("New summary")
	project.SetDescription("New description")
	c.Assert(project.Name(), Equals, "newname")
	c.Assert(project.DisplayName(), Equals, "New Display Name")
	c.Assert(project.Title(), Equals, "New Title")
	c.Assert(project.Summary(), Equals, "New summary")
	c.Assert(project.Description(), Equals, "New description")

	testServer.PrepareResponse(200, jsonType, `{"name": "seriesname"}`)
	series, err := project.FocusSeries()
	c.Assert(err, IsNil)
	c.Assert(series.Name(), Equals, "seriesname")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/focus_link")
}

func (s *ModelS) TestMilestone(c *C) {
	m := M{
		"name":          "thename",
		"code_name":     "thecodename",
		"title":         "Title",
		"summary":       "Summary",
		"date_targeted": "2011-08-31",
		"is_active":     true,
		"web_link":      "http://page",
	}

	ms := &lpad.Milestone{lpad.NewValue(nil, "", "", m)}
	c.Assert(ms.Name(), Equals, "thename")
	c.Assert(ms.CodeName(), Equals, "thecodename")
	c.Assert(ms.Title(), Equals, "Title")
	c.Assert(ms.Summary(), Equals, "Summary")
	c.Assert(ms.Date(), Equals, "2011-08-31")
	c.Assert(ms.Active(), Equals, true)
	c.Assert(ms.WebPage(), Equals, "http://page")
	ms.SetName("newname")
	ms.SetCodeName("newcodename")
	ms.SetTitle("New Title")
	ms.SetSummary("New summary")
	ms.SetDate("2011-09-01")
	ms.SetActive(false)
	c.Assert(ms.Name(), Equals, "newname")
	c.Assert(ms.CodeName(), Equals, "newcodename")
	c.Assert(ms.Title(), Equals, "New Title")
	c.Assert(ms.Summary(), Equals, "New summary")
	c.Assert(ms.Date(), Equals, "2011-09-01")
	c.Assert(ms.Active(), Equals, false)
}

func (s *ModelS) TestProjectSeries(c *C) {
	m := M{
		"name":        "thename",
		"title":       "Title",
		"summary":     "Summary",
		"is_active":   true,
		"web_link":    "http://page",
		"branch_link": testServer.URL + "/branch_link",
	}

	series := &lpad.ProjectSeries{lpad.NewValue(nil, "", "", m)}
	c.Assert(series.Name(), Equals, "thename")
	c.Assert(series.Title(), Equals, "Title")
	c.Assert(series.Summary(), Equals, "Summary")
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

	testServer.PrepareResponse(200, jsonType, `{"unique_name": "lp:thebranch"}`)

	b, err := series.Branch()
	c.Assert(err, IsNil)
	c.Assert(b.UniqueName(), Equals, "lp:thebranch")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/branch_link")

	b = &lpad.Branch{lpad.NewValue(nil, "", "/new_branch_link", nil)}
	series.SetBranch(b)
	c.Assert(series.StringField("branch_link"), Equals, "/new_branch_link")
}

func (s *ModelS) TestRootProject(c *C) {
	data := `{
		"name": "Name",
		"title": "Title",
		"description": "Description"
	}`
	testServer.PrepareResponse(200, jsonType, data)
	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}
	project, err := root.Project("myproj")
	c.Assert(err, IsNil)
	c.Assert(project.Name(), Equals, "Name")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/myproj")
}

func (s *ModelS) TestProjectActiveMilestones(c *C) {
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
	m := M{"active_milestones_collection_link": testServer.URL + "/col_link"}
	project := &lpad.Project{lpad.NewValue(nil, testServer.URL, "", m)}
	list, err := project.ActiveMilestones()
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

func (s *ModelS) TestProjectAllSeries(c *C) {
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
	m := M{"series_collection_link": testServer.URL + "/col_link"}
	project := &lpad.Project{lpad.NewValue(nil, testServer.URL, "", m)}
	list, err := project.AllSeries()
	c.Assert(err, IsNil)
	c.Assert(list.TotalSize(), Equals, 2)

	names := []string{}
	list.For(func(s *lpad.ProjectSeries) error {
		names = append(names, s.Name())
		return nil
	})
	c.Assert(names, DeepEquals, []string{"Name0", "Name1"})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/col_link")
}
