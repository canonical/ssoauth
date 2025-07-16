package lpad

// Archive represents a package archive.
type Archive struct {
	*Value
}

// Name returns the name of this archive.
func (a *Archive) Name() string {
	return a.StringField("name")
}

// DisplayName returns the user friendly name of this archive.
func (a *Archive) DisplayName() string {
	return a.StringField("displayname")
}

// Description returns a description string for this archive.
func (a *Archive) Description() string {
	return a.StringField("description")
}

// Distro returns the distribution that uses this archive.
func (a *Archive) Distro() (*Distro, error) {
	v, err := a.Link("distribution_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Distro{v}, nil
}

// WebPage returns the URL for accessing this archive in a browser.
func (a *Archive) WebPage() string {
	return a.StringField("web_link")
}

type PublishStatus string

const (
	PubPending    PublishStatus = "Pending"
	PubPublished  PublishStatus = "Published"
	PubSuperseded PublishStatus = "Superseded"
	PubDeleted    PublishStatus = "Deleted"
	PubObsolete   PublishStatus = "Obsolete"
)

// Publication returns the publication history for the sourceName
// source package in this archive that has the given status.
func (a *Archive) Publication(sourceName string, status PublishStatus) (*PublicationList, error) {
	params := Params{
		"ws.op":       "getPublishedSources",
		"source_name": sourceName,
		"exact_match": "true",
		"pocket":      "Release",
		"status":      string(status),
	}
	v, err := a.Location("").Get(params)
	if err != nil {
		return nil, err
	}
	return &PublicationList{v}, nil
}

// ArchiveList represents a list of Archive objects.
type ArchiveList struct {
	*Value
}

// For iterates over the list of archive objects and calls f for each one.
// If f returns a non-nil error, iteration will stop and the error will be
// returned as the result of For.
func (list *ArchiveList) For(f func(a *Archive) error) error {
	return list.Value.For(func(v *Value) error {
		return f(&Archive{v})
	})
}
