package lpad

// SourcePackage represents a source package associated to
// a particular distribution series.
type SourcePackage struct {
	*Value
}

// Name returns the package name.
func (s *SourcePackage) Name() string {
	return s.StringField("name")
}

// DisplayName returns the package display name.
func (s *SourcePackage) DisplayName() string {
	return s.StringField("displayname")
}

// LatestComponent returns the name of the component where the
// source package was last published.
func (s *SourcePackage) LatestComponent() string {
	return s.StringField("latest_published_component_name")
}

// WebPage returns the URL for accessing this source package in a browser.
func (s *SourcePackage) WebPage() string {
	return s.StringField("web_link")
}

// Distro returns the distribution for this source package.
func (s *SourcePackage) Distro() (*Distro, error) {
	d, err := s.Link("distribution_link").Get(nil)
	if err != nil {
		return nil, err
	}

	return &Distro{d}, nil
}

// DistroSeries returns the distribution series for the source package.
func (s *SourcePackage) DistroSeries() (*DistroSeries, error) {
	d, err := s.Link("distroseries_link").Get(nil)
	if err != nil {
		return nil, err
	}

	return &DistroSeries{d}, nil
}

// DistroSourcePackage represents a source package in a distribution.
type DistroSourcePackage struct {
	*Value
}

// Name returns the package name.
func (s *DistroSourcePackage) Name() string {
	return s.StringField("name")
}

// DisplayName returns the package display name.
func (s *DistroSourcePackage) DisplayName() string {
	return s.StringField("display_name")
}

// Title returns the package title.
func (s *DistroSourcePackage) Title() string {
	return s.StringField("title")
}

// WebPage returns the URL for accessing this source package in a browser.
func (s *DistroSourcePackage) WebPage() string {
	return s.StringField("web_link")
}

// Distro returns the distribution of this source package.
func (s *DistroSourcePackage) Distro() (*Distro, error) {
	d, err := s.Link("distribution_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Distro{d}, nil
}
