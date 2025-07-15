package lpad_test

import (
	. "gopkg.in/check.v1"
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
