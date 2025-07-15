package lpad_test

import (
	. "launchpad.net/gocheck"
)

var _ = Suite(&ModelS{})
var _ = Suite(&ModelI{})

type ModelS struct {
	HTTPSuite
}

type ModelI struct {
	SuiteI
}

type M map[string]interface{}
