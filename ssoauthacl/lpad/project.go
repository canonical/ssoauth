package lpad

import "net/url"

// Project returns a project with the given name.
func (root *Root) Project(name string) (*Project, error) {
	r, err := root.Location("/" + url.QueryEscape(name)).Get(nil)
	if err != nil {
		return nil, err
	}
	return &Project{r}, nil
}

// The Project type represents a project in Launchpad.
type Project struct {
	*Value
}

// Name returns the project name, which is composed of at least one
// lowercase letter or number, followed by letters, numbers, dots,
// hyphens or pluses. This is a short name used in URLs.
func (p *Project) Name() string {
	return p.StringField("name")
}

// DisplayName returns the project name as it would be displayed
// in a paragraph.  For example, a project's title might be
// "The Foo Project" and its display name could be "Foo".
func (p *Project) DisplayName() string {
	return p.StringField("display_name")
}

// Title returns the project title as it might be used in isolation.
// For example, a project's title might be "The Foo Project" and its
// display name could be "Foo".
func (p *Project) Title() string {
	return p.StringField("title")
}

// Summary returns the project summary, which is a short paragraph
// to introduce the project's work.
func (p *Project) Summary() string {
	return p.StringField("summary")
}

// Description returns the project description.
func (p *Project) Description() string {
	return p.StringField("description")
}

// WebPage returns the URL for accessing this project in a browser.
func (p *Project) WebPage() string {
	return p.StringField("web_link")
}

// SetName changes the project name, which must be composed of at
// least one lowercase letter or number, followed by letters, numbers,
// dots, hyphens or pluses. This is a short name used in URLs.
// Patch must be called to commit all changes.
func (p *Project) SetName(name string) {
	p.SetField("name", name)
}

// SetDisplayName changes the project name as it would be displayed
// in a paragraph. For example, a project's title might be
// "The Foo Project" and its display name could be "Foo".
// Patch must be called to commit all changes.
func (p *Project) SetDisplayName(name string) {
	p.SetField("display_name", name)
}

// SetTitle changes the project title as it would be displayed
// in isolation. For example, the project title might be
// "The Foo Project" and display name could be "Foo".
// Patch must be called to commit all changes.
func (p *Project) SetTitle(title string) {
	p.SetField("title", title)
}

// SetSummary changes the project summary, which is a short paragraph
// to introduce the project's work.
// Patch must be called to commit all changes.
func (p *Project) SetSummary(title string) {
	p.SetField("summary", title)
}

// SetDescription changes the project's description.
// Patch must be called to commit all changes.
func (p *Project) SetDescription(description string) {
	p.SetField("description", description)
}

// ActiveMilestones returns the list of active milestones associated with
// the project, ordered by the target date.
func (p *Project) ActiveMilestones() (*MilestoneList, error) {
	r, err := p.Link("active_milestones_collection_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &MilestoneList{r}, nil
}

// AllSeries returns the list of series associated with the project.
func (p *Project) AllSeries() (*ProjectSeriesList, error) {
	r, err := p.Link("series_collection_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &ProjectSeriesList{r}, nil
}

// FocusSeries returns the development series set as the current
// development focus.
func (p *Project) FocusSeries() (*ProjectSeries, error) {
	r, err := p.Link("development_focus_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &ProjectSeries{r}, nil
}

// BlueprintTarget marks *Project as being a target for blueprints. 
func (p *Project) BlueprintTarget() {}

// The Milestone type represents a milestone associated with a project
// or distribution.
type Milestone struct {
	*Value
}

// Name returns the milestone name, which consists of only
// letters, numbers, and simple punctuation.
func (ms *Milestone) Name() string {
	return ms.StringField("name")
}

// CodeName returns the alternative name for the milestone, if any.
func (ms *Milestone) CodeName() string {
	return ms.StringField("code_name")
}

// Title returns the milestone context title for pages.
func (ms *Milestone) Title() string {
	return ms.StringField("title")
}

// Summary returns the summary of features and status of this milestone.
func (ms *Milestone) Summary() string {
	return ms.StringField("summary")
}

// WebPage returns the URL for accessing this milestone in a browser.
func (ms *Milestone) WebPage() string {
	return ms.StringField("web_link")
}

// Active returns true if the milestone is still in active development.
func (ms *Milestone) Active() bool {
	return ms.BoolField("is_active")
}

// Date returns the target date for the milestone.
func (ms *Milestone) Date() string {
	return ms.StringField("date_targeted")
}

// SetName changes the milestone name, which must consists of
// only letters, numbers, and simple punctuation.
func (ms *Milestone) SetName(name string) {
	ms.SetField("name", name)
}

// SetCodeName sets the alternative name for the milestone.
func (ms *Milestone) SetCodeName(name string) {
	ms.SetField("code_name", name)
}

// SetTitle changes the milestone's context title for pages.
func (ms *Milestone) SetTitle(title string) {
	ms.SetField("title", title)
}

// SetSummary sets the summary of features and status of this milestone.
func (ms *Milestone) SetSummary(summary string) {
	ms.SetField("summary", summary)
}

// SetActive sets whether the milestone is still in active
// development or not.
func (ms Milestone) SetActive(active bool) {
	ms.SetField("is_active", active)
}

// SetDate changes the target date for the milestone.
func (ms *Milestone) SetDate(date string) {
	ms.SetField("date_targeted", date)
}

// The MilestoneList type represents a list of milestones that
// may be iterated over.
type MilestoneList struct {
	*Value
}

// For iterates over the list of milestones and calls f for each one.
// If f returns a non-nil error, iteration will stop and the error will
// be returned as the result of For.
func (list *MilestoneList) For(f func(m *Milestone) error) error {
	return list.Value.For(func(r *Value) error {
		return f(&Milestone{r})
	})
}

// The ProjectSeries type represents a series associated with a project.
type ProjectSeries struct {
	*Value
}

// Name returns the series name, which is a unique name that identifies
// it and is used in URLs. It consists of only lowercase letters, digits,
// and simple punctuation.  For example, "2.0" or "trunk".
func (s *ProjectSeries) Name() string {
	return s.StringField("name")
}

// Title returns the series context title for pages.
func (s *ProjectSeries) Title() string {
	return s.StringField("title")
}

// Summary returns the summary for this project series.
func (s *ProjectSeries) Summary() string {
	return s.StringField("summary")
}

// WebPage returns the URL for accessing this project series in a browser.
func (s *ProjectSeries) WebPage() string {
	return s.StringField("web_link")
}

// Active returns true if this project series is still in active development.
func (s *ProjectSeries) Active() bool {
	return s.BoolField("is_active")
}

// Branch returns the Bazaar branch associated with this project series.
func (s *ProjectSeries) Branch() (*Branch, error) {
	r, err := s.Link("branch_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Branch{r}, nil
}

// SetName changes the series name, which must consists of only letters,
// numbers, and simple punctuation. For example: "2.0" or "trunk".
func (s *ProjectSeries) SetName(name string) {
	s.SetField("name", name)
}

// SetTitle changes the series title.
func (s *ProjectSeries) SetTitle(title string) {
	s.SetField("title", title)
}

// SetSummary changes the summary for this project series.
func (s *ProjectSeries) SetSummary(summary string) {
	s.SetField("summary", summary)
}

// SetActive sets whether the series is still in active development or not.
func (s *ProjectSeries) SetActive(active bool) {
	s.SetField("is_active", active)
}

// SetBranch changes the Bazaar branch associated with this project series.
func (s *ProjectSeries) SetBranch(branch *Branch) {
	s.SetField("branch_link", branch.AbsLoc())
}

// The ProjectSeriesList represents a list of project series.
type ProjectSeriesList struct {
	*Value
}

// For iterates over the list of series and calls f for each one.
// If f returns a non-nil error, iteration will stop and the error will
// be returned as the result of For.
func (list *ProjectSeriesList) For(f func(s *ProjectSeries) error) error {
	return list.Value.For(func(r *Value) error {
		return f(&ProjectSeries{r})
	})
}
