package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
)

func (s *ModelS) TestRootMe(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"display_name": "Joe"}`)

	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}

	me, err := root.Me()
	c.Assert(err, IsNil)
	c.Assert(me.DisplayName(), Equals, "Joe")

	req := testServer.WaitRequest()
	c.Assert(req.URL.Path, Equals, "/people/+me")
}

func (s *ModelS) TestRootMemberPerson(c *C) {
	data := `{"display_name": "Joe"}`
	testServer.PrepareResponse(200, jsonType, data)
	testServer.PrepareResponse(200, jsonType, data)

	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}

	member, err := root.Member("joe")
	c.Assert(err, IsNil)
	person, ok := member.(*lpad.Person)
	c.Assert(ok, Equals, true)
	c.Assert(person.DisplayName(), Equals, "Joe")

	req := testServer.WaitRequest()
	c.Assert(req.URL.Path, Equals, "/~joe")
}

func (s *ModelS) TestRootMemberTeam(c *C) {
	data := `{"display_name": "Ensemble", "is_team": true}`
	testServer.PrepareResponse(200, jsonType, data)
	testServer.PrepareResponse(200, jsonType, data)

	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}

	member, err := root.Member("ensemble")
	c.Assert(err, IsNil)
	team, ok := member.(*lpad.Team)
	c.Assert(ok, Equals, true)
	c.Assert(team.DisplayName(), Equals, "Ensemble")

	req := testServer.WaitRequest()
	c.Assert(req.URL.Path, Equals, "/~ensemble")
}

func (s *ModelS) TestRootFindMembers(c *C) {
	data := `{
		"total_size": 2,
		"start": 0,
		"entries": [{
			"self_link": "http://self0",
			"display_name": "Name0",
			"is_team": false
		}, {
			"self_link": "http://self1",
			"display_name": "Name1",
			"is_team": true
		}]
	}`
	testServer.PrepareResponse(200, jsonType, data)
	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}
	list, err := root.FindMembers("someuser")
	c.Assert(err, IsNil)
	c.Assert(list.TotalSize(), Equals, 2)

	names := []string{}
	list.For(func(v lpad.Member) error {
		if v.BoolField("is_team") {
			t := v.(*lpad.Team)
			names = append(names, t.DisplayName())
		} else {
			p := v.(*lpad.Person)
			names = append(names, p.DisplayName())
		}
		return nil
	})
	c.Assert(names, DeepEquals, []string{"Name0", "Name1"})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/people")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"find"})
	c.Assert(req.Form["text"], DeepEquals, []string{"someuser"})
}

func (s *ModelS) TestRootFindPeople(c *C) {
	data := `{
		"total_size": 2,
		"start": 0,
		"entries": [{
			"self_link": "http://self0",
			"display_name": "Name0"
		}, {
			"self_link": "http://self1",
			"display_name": "Name1"
		}]
	}`
	testServer.PrepareResponse(200, jsonType, data)
	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}
	list, err := root.FindPeople("someuser")
	c.Assert(err, IsNil)
	c.Assert(list.TotalSize(), Equals, 2)

	names := []string{}
	list.For(func(p *lpad.Person) error {
		names = append(names, p.DisplayName())
		return nil
	})
	c.Assert(names, DeepEquals, []string{"Name0", "Name1"})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/people")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"findPerson"})
	c.Assert(req.Form["text"], DeepEquals, []string{"someuser"})
}

func (s *ModelS) TestRootFindTeams(c *C) {
	data := `{
		"total_size": 2,
		"start": 0,
		"entries": [{
			"self_link": "http://self0",
			"display_name": "Name0",
			"is_team": true
		}, {
			"self_link": "http://self1",
			"display_name": "Name1",
			"is_team": true
		}]
	}`
	testServer.PrepareResponse(200, jsonType, data)
	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}
	list, err := root.FindTeams("someuser")
	c.Assert(err, IsNil)
	c.Assert(list.TotalSize(), Equals, 2)

	names := []string{}
	list.For(func(t *lpad.Team) error {
		names = append(names, t.DisplayName())
		return nil
	})
	c.Assert(names, DeepEquals, []string{"Name0", "Name1"})

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/people")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"findTeam"})
	c.Assert(req.Form["text"], DeepEquals, []string{"someuser"})
}

func (s *ModelS) TestPerson(c *C) {
	m := M{
		"name":         "joe",
		"display_name": "Joe",
		"web_link":     "http://page",
	}
	person := &lpad.Person{lpad.NewValue(nil, "", "", m)}
	c.Assert(person.Name(), Equals, "joe")
	c.Assert(person.DisplayName(), Equals, "Joe")
	c.Assert(person.WebPage(), Equals, "http://page")
	person.SetName("newname")
	person.SetDisplayName("New Name")
	c.Assert(person.Name(), Equals, "newname")
	c.Assert(person.DisplayName(), Equals, "New Name")
}

func (s *ModelS) TestTeam(c *C) {
	m := M{
		"name":         "myteam",
		"display_name": "My Team",
		"web_link":     "http://page",
	}
	team := &lpad.Team{lpad.NewValue(nil, "", "", m)}
	c.Assert(team.Name(), Equals, "myteam")
	c.Assert(team.DisplayName(), Equals, "My Team")
	c.Assert(team.WebPage(), Equals, "http://page")
	team.SetName("ateam")
	team.SetDisplayName("A Team")
	c.Assert(team.Name(), Equals, "ateam")
	c.Assert(team.DisplayName(), Equals, "A Team")
}

func (s *ModelS) TestIRCNick(c *C) {
	m := M{
		"resource_type_link": "https://api.launchpad.net/1.0/#irc_id",
		"self_link":          "https://api.launchpad.net/1.0/~lpad-test/+ircnick/28983",
		"person_link":        "https://api.launchpad.net/1.0/~lpad-test",
		"web_link":           "https://api.launchpad.net/~lpad-test/+ircnick/28983",
		"nickname":           "canonical-nick",
		"network":            "irc.canonical.com",
		"http_etag":          "\"the-etag\"",
	}
	nick := &lpad.IRCNick{lpad.NewValue(nil, "", "", m)}
	c.Assert(nick.Nick(), Equals, "canonical-nick")
	c.Assert(nick.Network(), Equals, "irc.canonical.com")
}

func (s *ModelS) TestIRCNickChange(c *C) {
	nick := &lpad.IRCNick{lpad.NewValue(nil, "", "", nil)}
	nick.SetNick("mynick")
	nick.SetNetwork("mynetwork")
	c.Assert(nick.Nick(), Equals, "mynick")
	c.Assert(nick.Network(), Equals, "mynetwork")
}

func (s *ModelS) TestPersonNicks(c *C) {
	m := M{
		"irc_nicknames_collection_link": testServer.URL + "/~lpad-test/irc_nicknames",
	}
	data := `{
		"total_size": 2,
		"start": 0,
		"entries": [{
			"resource_type_link": "https://api.launchpad.net/1.0/#irc_id",
			"network": "irc.canonical.com",
			"person_link": "https://api.launchpad.net/1.0/~lpad-test",
			"web_link": "https://api.launchpad.net/~lpad-test/+ircnick/28983",
			"http_etag": "\"the-etag1\"",
			"self_link": "https://api.launchpad.net/1.0/~lpad-test/+ircnick/28983",
			"nickname": "canonical-nick"
		}, {
			"resource_type_link": "https://api.launchpad.net/1.0/#irc_id",
			"network": "irc.freenode.net",
			"person_link": "https://api.launchpad.net/1.0/~lpad-test",
			"web_link": "https://api.launchpad.net/~lpad-test/+ircnick/28982",
			"http_etag": "\"the-etag2\"",
			"self_link": "https://api.launchpad.net/1.0/~lpad-test/+ircnick/28982",
			"nickname": "freenode-nick"
		}],
		"resource_type_link": "https://api.launchpad.net/1.0/#irc_id-page-resource"
	}`
	testServer.PrepareResponse(200, jsonType, data)
	person := &lpad.Person{lpad.NewValue(nil, "", "", m)}
	nicks, err := person.IRCNicks()
	c.Assert(err, IsNil)
	c.Assert(len(nicks), Equals, 2)
	c.Assert(nicks[0].Nick(), Equals, "canonical-nick")
	c.Assert(nicks[1].Nick(), Equals, "freenode-nick")
}

func (s *ModelS) TestPersonPreferredEmail(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"email": "the@email.com"}`)
	m := M{"preferred_email_address_link": testServer.URL + "/link"}
	person := &lpad.Person{lpad.NewValue(nil, "", "", m)}
	email, err := person.PreferredEmail()
	c.Assert(err, IsNil)
	c.Assert(email, Equals, "the@email.com")

	req := testServer.WaitRequest()
	c.Assert(req.URL.Path, Equals, "/link")
}
