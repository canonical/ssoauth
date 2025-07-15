package lpad

import (
	"fmt"
	"net/url"
	"time"
)

// Distro returns a distribution with the given name.
func (root *Root) Distro(name string) (*Distro, error) {
	r, err := root.Location("/" + url.QueryEscape(name)).Get(nil)
	if err != nil {
		return nil, err
	}
	return &Distro{r}, nil
}

// Distros returns the list of all distributions registered in Launchpad.
func (root *Root) Distros() (*DistroList, error) {
	list, err := root.Location("/distros/").Get(nil)
	if err != nil {
		return nil, err
	}
	return &DistroList{list}, nil
}

// The Distro type represents a distribution in Launchpad.
type Distro struct {
	*Value
}

// The DistroList type represents a list of Distro objects.
type DistroList struct {
	*Value
}

// For iterates over the list of distributions and calls f for each one.
// If f returns a non-nil error, iteration will stop and the error will be
// returned as the result of For.
func (list *DistroList) For(f func(d *Distro) error) {
	list.Value.For(func(v *Value) error {
		return f(&Distro{v})
	})
}

// Name returns the distribution name, which is composed of at least one
// lowercase letter or number, followed by letters, numbers, dots,
// hyphens or pluses. This is a short name used in URLs.
func (d *Distro) Name() string {
	return d.StringField("name")
}

// DisplayName returns the distribution name as it would be displayed
// in a paragraph. For example, a distribution's title might be
// "The Foo Distro" and its display name could be "Foo".
func (d *Distro) DisplayName() string {
	return d.StringField("display_name")
}

// Title returns the distribution title as it might be used in isolation.
func (d *Distro) Title() string {
	return d.StringField("title")
}

// Summary returns the distribution summary, which is a short paragraph
// to introduce the distribution's goals and highlights.
func (d *Distro) Summary() string {
	return d.StringField("summary")
}

// Description returns the distribution description.
func (d *Distro) Description() string {
	return d.StringField("description")
}

// WebPage returns the URL for accessing this distribution in a browser.
func (d *Distro) WebPage() string {
	return d.StringField("web_link")
}

// BlueprintTarget marks *Distro as being a target for blueprints. 
func (p *Distro) BlueprintTarget() {}

type BranchTip struct {
	UniqueName     string
	Revision       string
	OfficialSeries []string
}

// BranchTips returns a list of all branches registered under the given
// distribution changed after the since time.  If since is the zero time,
// all branch tips in the distribution are returned.
func (d *Distro) BranchTips(since time.Time) (tips []BranchTip, err error) {
	params := Params{"ws.op": "getBranchTips"}
	if !since.IsZero() {
		params["since"] = since.In(time.UTC).Format(time.RFC3339)
	}
	v, err := d.Location("").Get(params)
	if err != nil {
		return nil, err
	}
	l, ok := v.Map()["value"].([]interface{})
	if !ok {
		return nil, fmt.Errorf(`map is missing "value" field`)
	}
	for i := range l {
		li, ok := l[i].([]interface{})
		if !ok || len(li) != 3 {
			return nil, fmt.Errorf("unsupported branch tip item: %#v", l[i])
		}
		url, ok1 := li[0].(string)
		rev, ok2 := li[1].(string)
		series, ok3 := li[2].([]interface{})
		if !ok2 {
			if li[1] == nil {
				// Branch without revisions.
				ok2 = true
			}
		}
		if !(ok1 && ok2 && ok3) {
			return nil, fmt.Errorf("unsupported branch tip item: %#v", l[i])
		}
		sseries := []string{}
		for i := range series {
			s, ok := series[i].(string)
			if !ok {
				return nil, fmt.Errorf("unsupported branch tip item: %#v", l[i])
			}
			sseries = append(sseries, s)
		}
		tips = append(tips, BranchTip{url, rev, sseries})
	}
	return tips, nil
}

// SetName changes the distribution name, which must be composed of at
// least one lowercase letter or number, followed by letters, numbers,
// dots, hyphens or pluses. This is a short name used in URLs.
// Patch must be called to commit all changes.
func (d *Distro) SetName(name string) {
	d.SetField("name", name)
}

// SetDisplayName changes the distribution name as it would be displayed
// in a paragraph. For example, a distribution's title might be
// "The Foo Distro" and its display name could be "Foo".
// Patch must be called to commit all changes.
func (d *Distro) SetDisplayName(name string) {
	d.SetField("display_name", name)
}

// SetTitle changes the distribution title as it would be displayed
// in isolation. For example, the distribution title might be
// "The Foo Distro" and display name could be "Foo".
// Patch must be called to commit all changes.
func (d *Distro) SetTitle(title string) {
	d.SetField("title", title)
}

// SetSummary changes the distribution summary, which is a short paragraph
// to introduce the distribution's goals and highlights.
// Patch must be called to commit all changes.
func (d *Distro) SetSummary(title string) {
	d.SetField("summary", title)
}

// SetDescription changes the distributions's description.
// Patch must be called to commit all changes.
func (d *Distro) SetDescription(description string) {
	d.SetField("description", description)
}

// ActiveMilestones returns the list of active milestones associated with
// the distribution, ordered by the target date.
func (d *Distro) ActiveMilestones() (*MilestoneList, error) {
	r, err := d.Link("active_milestones_collection_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &MilestoneList{r}, nil
}

// Series returns the named Series of this distribution.
func (d *Distro) Series(name string) (*DistroSeries, error) {
	s, err := d.Location(url.QueryEscape(name)).Get(nil)
	if err != nil {
		return nil, err
	}
	return &DistroSeries{s}, nil
}

// AllSeries returns the list of series associated with the distribution.
func (d *Distro) AllSeries() (*DistroSeriesList, error) {
	r, err := d.Link("series_collection_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &DistroSeriesList{r}, nil
}

// Archives returns the list of archives associated with the distribution.
func (d *Distro) Archives() (*ArchiveList, error) {
	r, err := d.Link("archives_collection_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &ArchiveList{r}, nil
}

// Archive returns the named archive associated with the distribution
func (d *Distro) Archive(name string) (*Archive, error) {
	v, err := d.Location("").Get(Params{"ws.op": "getArchive", "name": name})
	if err != nil {
		return nil, err
	}
	return &Archive{v}, nil
}

// FocusDistroSeries returns the distribution series set as the current
// development focus.
func (d *Distro) FocusSeries() (*DistroSeries, error) {
	r, err := d.Link("current_series_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &DistroSeries{r}, nil
}

// The DistroSeries type represents a series associated with a distribution.
type DistroSeries struct {
	*Value
}

// Name returns the series name, which is a unique name that identifies
// it and is used in URLs. It consists of only lowercase letters, digits,
// and simple punctuation.  For example, "2.0" or "trunk".
func (s *DistroSeries) Name() string {
	return s.StringField("name")
}

// DisplayName returns the distribution series display name (e.g. "Oneiric").
func (d *DistroSeries) DisplayName() string {
	return d.StringField("displayname")
}

// FullSeriesName returns the distribution series name as it would be displayed
// in a paragraph (e.g. "Oneiric Ocelot").
func (d *DistroSeries) FullSeriesName() string {
	return d.StringField("fullseriesname")
}

// Title returns the series context title for pages.
func (s *DistroSeries) Title() string {
	return s.StringField("title")
}

// Summary returns the summary for this distribution series.
func (s *DistroSeries) Summary() string {
	return s.StringField("summary")
}

// WebPage returns the URL for accessing this distribution series in a browser.
func (s *DistroSeries) WebPage() string {
	return s.StringField("web_link")
}

// Active returns true if this distribution series is still in active development.
func (s *DistroSeries) Active() bool {
	return s.BoolField("active")
}

// Description returns the distribution series' description.
func (d DistroSeries) Description() string {
	return d.StringField("description")
}

// TODO: These have no tests.
//
//type TagMatching string
//
//const (
//	MatchAny TagMatching = "Any"
//	MatchAll TagMatching = "All"
//)
//
//// SearchTasks returns the list of bug tasks associated with this
//// distribution that match the given criteria.
//func (d *Distro) SearchTasks(tags string, matching TagMatching) (*BugTaskList, error) {
//	params := Params{
//		"ws.op": "searchTasks",
//		"tags": tags,
//		"tags_combinator": string(matching),
//	}
//	v, err := d.Location("").Get(params)
//	if err != nil {
//		return nil, err
//	}
//	return &BugTaskList{v}, nil
//}
//
//// SearchTasks returns the list of bug tasks associated with this
//// distribution series that match the given criteria.
//func (d *DistroSeries) SearchTasks(tags string, matching TagMatching) (*BugTaskList, error) {
//	params := Params{
//		"ws.op": "searchTasks",
//		"tags": tags,
//		"tags_combinator": string(match),
//	}
//	v, err := d.Location("").Get(params)
//	if err != nil {
//		return nil, err
//	}
//	return &BugTaskList{v}, nil
//}
//
//// Builds returns a list of all the Build objects for this distribution
//// series for the source packages matching the given criteria.
//func (d *DistroSeries) Builds(buildState BuildState, pocket Pocket, sourceName string) (*BuildList, error) {
//	params := Params{
//		"ws.op": "getBuildRecords",
//		"build_state": string(buildState),
//		"source_name": sourceName,
//	}
//	if pocket != PocketAny {
//		params["pocket"] = string(pocket)
//	}
//	v, err := d.Location("").Get(params)
//	if err != nil {
//		return nil, err
//	}
//	return &BuildList{v}, nil
//}

// DistroSourcePackage returns the DistroSourcePackage with the given name.
func (d *Distro) DistroSourcePackage(name string) (*DistroSourcePackage, error) {
	params := Params{"ws.op": "getSourcePackage", "name": name}
	v, err := d.Location("").Get(params)
	if err != nil {
		return nil, err
	}
	return &DistroSourcePackage{v}, nil
}

// SourcePackage returns the SourcePackage with the given name.
func (d *DistroSeries) SourcePackage(name string) (*SourcePackage, error) {
	params := Params{"ws.op": "getSourcePackage", "name": name}
	v, err := d.Location("").Get(params)
	if err != nil {
		return nil, err
	}
	return &SourcePackage{v}, nil
}

// SetName changes the series name, which must consists of only letters,
// numbers, and simple punctuation. For example: "2.0" or "trunk".
func (s *DistroSeries) SetName(name string) {
	s.SetField("name", name)
}

// SetTitle changes the series title.
func (s *DistroSeries) SetTitle(title string) {
	s.SetField("title", title)
}

// SetSummary changes the summary for this distribution series.
func (s *DistroSeries) SetSummary(summary string) {
	s.SetField("summary", summary)
}

// SetActive sets whether the series is still in active development or not.
func (s *DistroSeries) SetActive(active bool) {
	s.SetField("active", active)
}

// The DistroSeriesList represents a list of distribution series.
type DistroSeriesList struct {
	*Value
}

// For iterates over the list of series and calls f for each one.
// If f returns a non-nil error, iteration will stop and the error will
// be returned as the result of For.
func (list *DistroSeriesList) For(f func(s *DistroSeries) error) error {
	return list.Value.For(func(r *Value) error {
		return f(&DistroSeries{r})
	})
}
