package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
)

func (s *ModelS) TestBug(c *C) {
	m := M{
		"id":               123456.0,
		"title":            "Title",
		"description":      "Description",
		"tags":             []interface{}{"a", "b", "c"},
		"private":          true,
		"security_related": true,
		"web_link":         "http://page",
	}
	bug := &lpad.Bug{lpad.NewValue(nil, "", "", m)}
	c.Assert(bug.Id(), Equals, 123456)
	c.Assert(bug.Title(), Equals, "Title")
	c.Assert(bug.Description(), Equals, "Description")
	c.Assert(bug.Tags(), DeepEquals, []string{"a", "b", "c"})
	c.Assert(bug.Private(), Equals, true)
	c.Assert(bug.SecurityRelated(), Equals, true)
	c.Assert(bug.WebPage(), Equals, "http://page")
	bug.SetTitle("New title")
	bug.SetDescription("New description")
	bug.SetTags([]string{"new", "tags"})
	bug.SetPrivate(false)
	bug.SetSecurityRelated(false)
	c.Assert(bug.Title(), Equals, "New title")
	c.Assert(bug.Description(), Equals, "New description")
	c.Assert(bug.Tags(), DeepEquals, []string{"new", "tags"})
	c.Assert(bug.Private(), Equals, false)
	c.Assert(bug.SecurityRelated(), Equals, false)
}

func (s *ModelS) TestBugTask(c *C) {
	m := M{
		"assignee_link":  testServer.URL + "/assignee_link",
		"milestone_link": testServer.URL + "/milestone_link",
		"status":         "New",
		"importance":     "High",
	}
	task := &lpad.BugTask{lpad.NewValue(nil, "", "", m)}

	c.Assert(task.Status(), Equals, lpad.StNew)
	c.Assert(task.Importance(), Equals, lpad.ImHigh)
	task.SetStatus(lpad.StInProgress)
	task.SetImportance(lpad.ImCritical)
	c.Assert(task.Status(), Equals, lpad.StInProgress)
	c.Assert(task.Importance(), Equals, lpad.ImCritical)

	testServer.PrepareResponse(200, jsonType, `{"display_name": "Joe"}`)
	testServer.PrepareResponse(200, jsonType, `{"name": "mymiles"}`)

	assignee, err := task.Assignee()
	c.Assert(err, IsNil)
	c.Assert(assignee.DisplayName(), Equals, "Joe")

	milestone, err := task.Milestone()
	c.Assert(err, IsNil)
	c.Assert(milestone.Name(), Equals, "mymiles")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/assignee_link")

	req = testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/milestone_link")

	milestone = &lpad.Milestone{lpad.NewValue(nil, "", "/new_milestone_link", nil)}
	assignee = &lpad.Person{lpad.NewValue(nil, "", "/new_assignee_link", nil)}

	task.SetMilestone(milestone)
	task.SetAssignee(assignee)

	c.Assert(task.StringField("milestone_link"), Equals, "/new_milestone_link")
	c.Assert(task.StringField("assignee_link"), Equals, "/new_assignee_link")
}

func (s *ModelS) TestRootBug(c *C) {
	data := `{
		"id": 123456,
		"title": "Title",
		"description": "Description",
		"private": true,
		"security_related": true,
		"tags": "a b c"
	}`
	testServer.PrepareResponse(200, jsonType, data)
	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}
	bug, err := root.Bug(123456)
	c.Assert(err, IsNil)
	c.Assert(bug.Title(), Equals, "Title")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/bugs/123456")
}

func (s *ModelS) TestRootCreateBug(c *C) {
	data := `{
		"id": 123456,
		"title": "Title",
		"description": "Description",
		"private": true,
		"security_related": true,
		"tags": "a b c"
	}`
	testServer.PrepareResponse(200, jsonType, data)
	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}
	stub := &lpad.BugStub{
		Title:           "Title",
		Description:     "Description.",
		Private:         true,
		SecurityRelated: true,
		Tags:            []string{"a", "b", "c"},
		Target:          lpad.NewValue(nil, "", "http://target", nil),
	}
	bug, err := root.CreateBug(stub)
	c.Assert(err, IsNil)
	c.Assert(bug.Title(), Equals, "Title")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/bugs")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"createBug"})
	c.Assert(req.Form["title"], DeepEquals, []string{"Title"})
	c.Assert(req.Form["description"], DeepEquals, []string{"Description."})
	c.Assert(req.Form["private"], DeepEquals, []string{"true"})
	c.Assert(req.Form["security_related"], DeepEquals, []string{"true"})
	c.Assert(req.Form["tags"], DeepEquals, []string{"a b c"})
	c.Assert(req.Form["target"], DeepEquals, []string{"http://target"})
}

func (s *ModelS) TestRootCreateBugNoTags(c *C) {
	// Launchpad blows up if an empty tags value is provided. :-(
	data := `{
		"id": 123456,
		"title": "Title"
	}`
	testServer.PrepareResponse(200, jsonType, data)
	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}
	stub := &lpad.BugStub{
		Title:       "Title",
		Description: "Description.",
		Target:      lpad.NewValue(nil, "", "http://target", nil),
	}
	bug, err := root.CreateBug(stub)
	c.Assert(err, IsNil)
	c.Assert(bug.Title(), Equals, "Title")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/bugs")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"createBug"})

	_, ok := req.Form["tags"]
	c.Assert(ok, Equals, false)
}

func (s *ModelS) TestBugLinkBranch(c *C) {
	testServer.PrepareResponse(200, jsonType, `{}`)
	bug := &lpad.Bug{lpad.NewValue(nil, "", testServer.URL+"/bugs/123456", nil)}
	branch := &lpad.Branch{lpad.NewValue(nil, testServer.URL, testServer.URL+"~joe/ensemble/some-branch", nil)}

	err := bug.LinkBranch(branch)
	c.Assert(err, IsNil)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/bugs/123456")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"linkBranch"})
	c.Assert(req.Form["branch"], DeepEquals, []string{branch.AbsLoc()})
}

func (s *ModelS) TestBugTasks(c *C) {
	data := `{
		"total_size": 2,
		"start": 0,
		"entries": [{
			"self_link": "http://self0",
			"status": "New"
		}, {
			"self_link": "http://self1",
			"status": "Unknown"
		}]
	}`
	testServer.PrepareResponse(200, jsonType, data)
	m := M{"bug_tasks_collection_link": testServer.URL + "/col_link"}
	bug := &lpad.Bug{lpad.NewValue(nil, testServer.URL, "", m)}
	list, err := bug.Tasks()
	c.Assert(err, IsNil)
	c.Assert(list.TotalSize(), Equals, 2)

	status := []lpad.BugStatus{}
	list.For(func(task *lpad.BugTask) error {
		status = append(status, task.Status())
		return nil
	})
	c.Assert(status, DeepEquals, []lpad.BugStatus{lpad.StNew, lpad.StUnknown})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/col_link")
}
