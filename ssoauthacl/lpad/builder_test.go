package lpad_test

import (
	. "launchpad.net/gocheck"
	"launchpad.net/lpad"
)

func (s *ModelS) TestBuilder(c *C) {
	m := M{
		"name":        "thename",
		"title":       "Title",
		"active":      true,
		"builderok":   true,
		"virtualized": "false",
		"vm_host":     "foobar",
		"web_link":    "http://page",
	}
	builder := &lpad.Builder{lpad.NewValue(nil, "", "", m)}
	c.Assert(builder.Name(), Equals, "thename")
	c.Assert(builder.Title(), Equals, "Title")
	c.Assert(builder.Active(), Equals, true)
	c.Assert(builder.BuilderOK(), Equals, true)
	c.Assert(builder.Virtualized(), Equals, false)
	c.Assert(builder.VMHost(), Equals, "foobar")
	c.Assert(builder.WebPage(), Equals, "http://page")
}

func (s *ModelS) TestRootBuildersAndBuilderList(c *C) {
	data := `{
		"total_size": 2,
		"start": 0,
		"entries": [
			{"name": "builder1", "builderok": true},
			{"name": "builder2", "builderok": true}
		]
        }`

	testServer.PrepareResponse(200, jsonType, data)
	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}

	builders, err := root.Builders()
	c.Assert(err, IsNil)
	var l []*lpad.Builder
	builders.For(func(builder *lpad.Builder) error {
		l = append(l, builder)
		return nil
	})

	c.Assert(len(l), Equals, 2)
	c.Assert(l[0].Name(), Equals, "builder1")
	c.Assert(l[1].Name(), Equals, "builder2")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/builders")
}

func (s *ModelS) TestRootBuilder(c *C) {
	testServer.PrepareResponse(200, jsonType, `{"name": "builder1"}`)
	root := &lpad.Root{lpad.NewValue(nil, testServer.URL, "", nil)}

	builder, err := root.Builder("builder1")
	c.Assert(err, IsNil)
	c.Assert(builder.Name(), Equals, "builder1")

	req := testServer.WaitRequest()
	c.Assert(req.Method, Equals, "GET")
	c.Assert(req.URL.Path, Equals, "/builders")
	c.Assert(req.Form["ws.op"], DeepEquals, []string{"getByName"})
	c.Assert(req.Form["name"], DeepEquals, []string{"builder1"})
}
