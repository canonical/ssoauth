package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
)

func (s *ModelS) TestBranch(c *C) {
	m := M{
		"bzr_identity":   "lp:~joe/ensemble",
		"unique_name":    "~joe/ensemble/some-branch",
		"web_link":       "http://page",
		"revision_count": float64(12),
	}
	branch := &lpad.Branch{lpad.NewValue(nil, "", "", m)}
	c.Assert(branch.Id(), Equals, "lp:~joe/ensemble")
	c.Assert(branch.UniqueName(), Equals, "~joe/ensemble/some-branch")
	c.Assert(branch.WebPage(), Equals, "http://page")
	c.Assert(branch.OwnerName(), Equals, "joe")
	c.Assert(branch.ProjectName(), Equals, "ensemble")
	c.Assert(branch.RevisionCount(), Equals, 12)
}

func (s *ModelS) TestRootBranch(c *C) {
	data := `{"unique_name": "~branch"}`
	testServer.PrepareResponse(200, jsonType, data)

	root := lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}

	branch, err := root.Branch("lp:~joe/project/branch-name")
	c.Assert(err, IsNil)
	c.Assert(branch.UniqueName(), Equals, "~branch")

	req := testServer.WaitRequest()
	c.Assert(req.URL.Path, Equals, "/branches")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"getByUrl"})
	c.Assert(req.Form["url"], DeepEquals, []string{"lp:~joe/project/branch-name"})

	testServer.PrepareResponse(200, jsonType, data)
	_, err = root.Branch("lp:~joe/+junk/foo")
	c.Assert(err, IsNil)
	req = testServer.WaitRequest()
	c.Assert(req.Form["url"], DeepEquals, []string{"lp:~joe/+junk/foo"})

	testServer.PrepareResponse(200, jsonType, data)
	_, err = root.Branch("lp:~joe/%2Bjunk/foo")
	c.Assert(err, IsNil)
	req = testServer.WaitRequest()
	c.Assert(req.Form["url"], DeepEquals, []string{"lp:~joe/+junk/foo"})

	testServer.PrepareResponse(200, jsonType, data)
	_, err = root.Branch("bzr+ssh://bazaar.launchpad.net/%2Bbranch/foo")
	c.Assert(err, IsNil)
	req = testServer.WaitRequest()
	c.Assert(req.Form["url"], DeepEquals, []string{"lp:foo"})

	testServer.PrepareResponse(200, jsonType, data)
	_, err = root.Branch("bzr+ssh://bazaar.launchpad.net/+branch/foo")
	c.Assert(err, IsNil)
	req = testServer.WaitRequest()
	c.Assert(req.Form["url"], DeepEquals, []string{"lp:foo"})
}

func (s *ModelS) TestMergeProposal(c *C) {
	m := M{
		"description":              "Description",
		"commit_message":           "Commit message",
		"queue_status":             "Needs review",
		"address":                  "some@email.com",
		"web_link":                 "http://page",
		"prerequisite_branch_link": testServer.URL + "/prereq_link",
		"target_branch_link":       testServer.URL + "/target_link",
		"source_branch_link":       testServer.URL + "/source_link",
	}
	mp := &lpad.MergeProposal{lpad.NewValue(nil, "", "", m)}
	c.Assert(mp.Description(), Equals, "Description")
	c.Assert(mp.CommitMessage(), Equals, "Commit message")
	c.Assert(mp.Status(), Equals, lpad.StNeedsReview)
	c.Assert(mp.Email(), Equals, "some@email.com")
	c.Assert(mp.WebPage(), Equals, "http://page")

	mp.SetDescription("New description")
	mp.SetCommitMessage("New message")
	c.Assert(mp.Description(), Equals, "New description")
	c.Assert(mp.CommitMessage(), Equals, "New message")

	testServer.PrepareResponse(200, jsonType, `{"unique_name": "branch1"}`)
	testServer.PrepareResponse(200, jsonType, `{"unique_name": "branch2"}`)
	testServer.PrepareResponse(200, jsonType, `{"unique_name": "branch3"}`)

	b1, err := mp.Target()
	c.Assert(err, IsNil)
	c.Assert(b1.UniqueName(), Equals, "branch1")

	b2, err := mp.PreReq()
	c.Assert(err, IsNil)
	c.Assert(b2.UniqueName(), Equals, "branch2")

	b3, err := mp.Source()
	c.Assert(err, IsNil)
	c.Assert(b3.UniqueName(), Equals, "branch3")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/target_link")

	req = testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/prereq_link")

	req = testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/source_link")
}

func (s *ModelS) TestMergeProposalSetStatus(c *C) {
	testServer.PrepareResponse(200, jsonType, `{}`)

	mp := &lpad.MergeProposal{lpad.NewValue(nil, testServer.URL, testServer.URL+"/mp", nil)}

	err := mp.SetStatus(lpad.StWorkInProgress)
	c.Assert(err, IsNil)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/mp")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"setStatus"})
	c.Assert(req.Form["status"], DeepEquals, []string{"Work in progress"})
}

func (s *ModelS) TestMergeProposalAddComment(c *C) {
	testServer.PrepareResponse(200, jsonType, `{}`)
	testServer.PrepareResponse(200, jsonType, `{}`)

	mp := &lpad.MergeProposal{lpad.NewValue(nil, testServer.URL, testServer.URL+"/mp", nil)}

	err := mp.AddComment("Subject", "", lpad.VoteNone, "")
	c.Assert(err, IsNil)

	err = mp.AddComment("Subject", "Message.", lpad.VoteNeedsFixing, "QA")
	c.Assert(err, IsNil)

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/mp")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"createComment"})
	c.Assert(req.Form["subject"], DeepEquals, []string{"Subject"})

	req = testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/mp")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"createComment"})
	c.Assert(req.Form["subject"], DeepEquals, []string{"Subject"})
	c.Assert(req.Form["content"], DeepEquals, []string{"Message."})
	c.Assert(req.Form["vote"], DeepEquals, []string{"Needs Fixing"})
	c.Assert(req.Form["review_type"], DeepEquals, []string{"QA"})
}

func (s *ModelS) TestBranchProposeMerge(c *C) {
	data := `{"description": "Description"}`
	testServer.PrepareResponse(200, jsonType, data)
	branch := &lpad.Branch{lpad.NewValue(nil, testServer.URL, testServer.URL+"/~joe/ensemble/some-branch", nil)}
	target := &lpad.Branch{lpad.NewValue(nil, testServer.URL, testServer.URL+"/~ensemble/ensemble/trunk", nil)}

	stub := &lpad.MergeStub{
		Description:   "Description",
		CommitMessage: "Commit message",
		NeedsReview:   true,
		Target:        target,
	}

	mp, err := branch.ProposeMerge(stub)
	c.Assert(err, IsNil)
	c.Assert(mp.Description(), Equals, "Description")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/~joe/ensemble/some-branch")
	c.Assert(req.Form["commit_message"], DeepEquals, []string{"Commit message"})
	c.Assert(req.Form["initial_comment"], DeepEquals, []string{"Description"})
	c.Assert(req.Form["needs_review"], DeepEquals, []string{"true"})
	c.Assert(req.Form["target_branch"], DeepEquals, []string{target.AbsLoc()})
}

func (s *ModelS) TestBranchProposeMergePreReq(c *C) {
	data := `{"description": "Description"}`
	testServer.PrepareResponse(200, jsonType, data)
	branch := &lpad.Branch{lpad.NewValue(nil, testServer.URL, testServer.URL+"/~joe/ensemble/some-branch", nil)}
	target := &lpad.Branch{lpad.NewValue(nil, testServer.URL, testServer.URL+"~ensemble/ensemble/trunk", nil)}
	prereq := &lpad.Branch{lpad.NewValue(nil, testServer.URL, testServer.URL+"~ensemble/ensemble/prereq", nil)}

	stub := &lpad.MergeStub{
		Target: target,
		PreReq: prereq,
	}

	mp, err := branch.ProposeMerge(stub)
	c.Assert(err, IsNil)
	c.Assert(mp.Description(), Equals, "Description")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "POST")
	c.Assert(req.URL.Path, Equals, "/~joe/ensemble/some-branch")
	c.Assert(req.Form["commit_message"], IsNil)
	c.Assert(req.Form["initial_comment"], IsNil)
	c.Assert(req.Form["needs_review"], DeepEquals, []string{"false"})
	c.Assert(req.Form["target_branch"], DeepEquals, []string{target.AbsLoc()})
	c.Assert(req.Form["prerequisite_branch"], DeepEquals, []string{prereq.AbsLoc()})
}

const mpList = `{
	"total_size": 2,
	"start": 0,
	"entries": [{
		"self_link": "http://self0",
		"description": "Desc0"
	}, {
		"self_link": "http://self1",
		"description": "Desc1"
	}]
}`

func checkMPList(c *C, list *lpad.MergeProposalList) {
	descs := []string{}
	list.For(func(mp *lpad.MergeProposal) error {
		descs = append(descs, mp.Description())
		return nil
	})
	c.Assert(descs, DeepEquals, []string{"Desc0", "Desc1"})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/link")
}

func (s *ModelS) TestLandingTargets(c *C) {
	testServer.PrepareResponse(200, jsonType, mpList)
	m := M{"landing_targets_collection_link": testServer.URL + "/link"}
	branch := &lpad.Branch{lpad.NewValue(nil, "", "", m)}
	list, err := branch.LandingTargets()
	c.Assert(err, IsNil)
	checkMPList(c, list)
}

func (s *ModelS) TestLandingCandidates(c *C) {
	testServer.PrepareResponse(200, jsonType, mpList)
	m := M{"landing_candidates_collection_link": testServer.URL + "/link"}
	branch := &lpad.Branch{lpad.NewValue(nil, "", "", m)}
	list, err := branch.LandingCandidates()
	c.Assert(err, IsNil)
	checkMPList(c, list)
}

func (s *ModelS) TestBranchOwner(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"display_name": "Joe"}`)
	m := M{"owner_link": testServer.URL + "/link"}
	branch := &lpad.Branch{lpad.NewValue(nil, "", "", m)}
	owner, err := branch.Owner()
	c.Assert(err, IsNil)
	c.Assert(owner.DisplayName(), Equals, "Joe")

	req := testServer.WaitRequest()
	c.Assert(req.URL.Path, Equals, "/link")
}
