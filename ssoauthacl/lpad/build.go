package lpad

import (
	"fmt"
	"net/url"
)

// A BuildState holds the state a package build can be found in.
type BuildState string

const (
	BSNeedsBuilding            BuildState = "Needs building"
	BSSuccessfullyBuilt        BuildState = "Successfully built"
	BSFailedToBuild            BuildState = "Failed to build"
	BSDependencyWait           BuildState = "Dependency wait"
	BSChrootProblem            BuildState = "Chroot problem"
	BSBuildForSupersededSource BuildState = "Build for superseded source"
	BSCurrentlyBuilding        BuildState = "Currently building"
	BSFailedToUpload           BuildState = "Failed to upload"
	BSCurrentlyUploading       BuildState = "Currently uploading"
)

// A Pocket represents the various distribution pockets where packages end up.
type Pocket string

const (
	PocketAny       Pocket = ""
	PocketRelease   Pocket = "Release"
	PocketSecurity  Pocket = "Security"
	PocketUpdates   Pocket = "Updates"
	PocketProposed  Pocket = "Proposed"
	PocketBackports Pocket = "Backports"
)

// The Build type describes a package build.
type Build struct {
	*Value
}

// The BuildList type represents a list of package Build objects.
type BuildList struct {
	*Value
}

// For iterates over the list of package builds and calls f for each one.
// If f returns a non-nil error, iteration will stop and the error will be
// returned as the result of For.
func (bl *BuildList) For(f func(b *Build) error) error {
	return bl.Value.For(func(v *Value) error {
		return f(&Build{v})
	})
}

// Build returns the identified package build.
func (root *Root) Build(distro string, source string, version string, id int) (*Build, error) {
	distro = url.QueryEscape(distro)
	source = url.QueryEscape(source)
	version = url.QueryEscape(version)
	path := fmt.Sprintf("/%s/+source/%s/%s/+build/%d/", distro, source, version, id)
	v, err := root.Location(path).Get(nil)
	if err != nil {
		return nil, err
	}
	return &Build{v}, nil
}

// Title returns the build title.
func (build *Build) Title() string {
	return build.StringField("title")
}

// Arch returns the architecture of build.
func (build *Build) Arch() string {
	return build.StringField("arch_tag")
}

// Retry sends a failed build back to the builder farm.
func (build *Build) Retry() error {
	_, err := build.Post(Params{"ws.op": "retry"})
	return err
}

// WebPage returns the URL for accessing this build in a browser.
func (build *Build) WebPage() string {
	return build.StringField("web_link")
}

// State returns the state of build.
func (build *Build) State() BuildState {
	return BuildState(build.StringField("buildstate"))
}

// BuildLogURL returns the URL for the build log file.
func (build *Build) BuildLogURL() string {
	return build.StringField("build_log_url")
}

// UploadLogURL returns the URL for the upload log if there was an upload failure.
func (build *Build) UploadLogURL() string {
	return build.StringField("upload_log_url")
}

// Created returns the timestamp when the build farm job was created.
func (build *Build) Created() string {
	return build.StringField("datecreated")
}

// Finished returns the timestamp when the build farm job was finished.
func (build *Build) Finished() string {
	return build.StringField("datebuilt")
}

// The Publication type holds a source package's publication record.
type Publication struct {
	*Value
}

// Publication returns the source publication record corresponding to build.
func (build *Build) Publication() (*Publication, error) {
	v, err := build.Link("current_source_publication_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Publication{v}, nil
}

// PackageName returns the name of the published source package.
func (p *Publication) PackageName() string {
	return p.StringField("source_package_name")
}

// PackageName returns the version of the published source package.
func (p *Publication) PackageVersion() string {
	return p.StringField("source_package_version")
}

// DistroSeries returns the distro series published into.
func (p *Publication) DistroSeries() (*DistroSeries, error) {
	v, err := p.Link("distro_series_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &DistroSeries{v}, nil
}

// Archive returns the archive published into.
func (p *Publication) Archive() (*Archive, error) {
	v, err := p.Link("archive_link").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Archive{v}, nil
}

// Component returns the component name published into.
func (p *Publication) Component() string {
	return p.StringField("component_name")
}

// PublicationList represents a list of Publication objects.
type PublicationList struct {
	*Value
}

// For iterates over the list of publication objects and calls f for
// each one. If f returns a non-nil error, iteration will stop and the
// error will be returned as the result of For.
func (list *PublicationList) For(f func(s *Publication) error) error {
	return list.Value.For(func(v *Value) error {
		return f(&Publication{v})
	})
}
