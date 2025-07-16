package lpad

import (
	"fmt"
)


// BlueprintTarget is implemented by types that may be used as
// targets for blueprints, such as *Project and *Distro.
type BlueprintTarget interface {
	Name() string
	BlueprintTarget()
}

// Blueprint returns the named blueprint associated with target.
func (root *Root) Blueprint(target BlueprintTarget, name string) (*Blueprint, error) {
	v, err := root.Location(fmt.Sprintf("/%s/+spec/%s", target.Name(), name)).Get(nil)
	if err != nil {
		return nil, err
	}
	return &Blueprint{v}, nil
}

// The Blueprint type represents a blueprint in Launchpad.
type Blueprint struct {
	*Value
}

// Name returns the blueprint name. May contain lower-case letters, numbers,
// and dashes. It will be used in the specification url.
// Examples: mozilla-type-ahead-find, postgres-smart-serial.
func (bp *Blueprint) Name() string {
	return bp.StringField("name")
}

// SetName changes the blueprint name which must consist of lower-case
// letters, numbers, and dashes. It will be used in the specification url.
// Examples: mozilla-type-ahead-find, postgres-smart-serial.
// Patch must be called to commit all changes.
func (bp *Blueprint) SetName(name string) {
	bp.SetField("name", name)
}

// Title returns the blueprint title that should describe the feature
// as clearly as possible, in up to 70 characters. This title is
// displayed in every feature list or report.
func (bp *Blueprint) Title() string {
	return bp.StringField("title")
}

// SetTitle sets the blueprint title.  The title must describe the feature
// as clearly as possible, in up to 70 characters. This title is displayed
// in every feature list or report.
func (bp *Blueprint) SetTitle(title string) {
	bp.SetField("title", title)
}

// Summary returns the blueprint summary which should consist of a single
// paragraph description of the feature.
func (bp *Blueprint) Summary() string {
	return bp.StringField("summary")
}

// SetSummary changes the blueprint summary which must consist of a single
// paragraph description of the feature.
func (bp *Blueprint) SetSummary(summary string) {
	bp.SetField("summary", summary)
}

// Whiteboard returns the blueprint whiteboard which contains any notes
// on the status of this specification.
func (bp *Blueprint) Whiteboard() string {
	return bp.StringField("whiteboard")
}

// SetWhiteboard changes the blueprint whiteboard that may contain any
// notes on the status of this specification.
func (bp *Blueprint) SetWhiteboard(whiteboard string) {
	bp.SetField("whiteboard", whiteboard)
}

// WebPage returns the URL for accessing this blueprint in a browser.
func (bp *Blueprint) WebPage() string {
	return bp.StringField("web_link")
}

// LinkBranch associates a branch with this blueprint.
func (bp *Blueprint) LinkBranch(branch *Branch) error {
	params := Params{
		"ws.op":  "linkBranch",
		"branch": branch.AbsLoc(),
	}
	_, err := bp.Post(params)
	return err
}

// LinkBug associates a bug with this blueprint.
func (bp *Blueprint) LinkBug(bug *Bug) error {
	params := Params{
		"ws.op": "linkBug",
		"bug":   bug.AbsLoc(),
	}
	_, err := bp.Post(params)
	return err
}
