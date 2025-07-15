package lpad

// API for: https://launchpad.net/builders
//
// Not all info presented on that page is available via the LP API though.

// Builders returns all the builders.
func (root *Root) Builders() (*BuilderList, error) {
	v, err := root.Location("/builders").Get(nil)
	if err != nil {
	    return nil, err
	}
	return &BuilderList{v}, nil
}

// Builder returns a builder by its name.
func (root *Root) Builder(name string) (*Builder, error) {
	v, err := root.Location("/builders").Get(Params{"ws.op": "getByName", "name": name})
	if err != nil {
	    return nil, err
	}
	return &Builder{v}, nil
}

// The Builder type stands for an individual machine that builds packages.
type Builder struct {
	*Value
}

// Name returns the builder's name.
func (b *Builder) Name() string {
	return b.StringField("name")
}

// Title returns the builder slave title.
func (b *Builder) Title() string {
	return b.StringField("title")
}

// Active returns whether the builder is enabled.
func (b *Builder) Active() bool {
	return b.BoolField("active")
}

// BuilderOK returns whether the builder is working fine.
func (b *Builder) BuilderOK() bool {
	return b.BoolField("builderok")
}

// Virtualized returns whether the builder is virtualized Xen instance.
func (b *Builder) Virtualized() bool {
	return b.BoolField("virtualized")
}

// VMHost returns the machine hostname hosting the builder.
func (b *Builder) VMHost() string {
	return b.StringField("vm_host")
}

// WebPage returns the URL for accessing this builder in a browser.
func (b *Builder) WebPage() string {
	return b.StringField("web_link")
}

// A BuilderList represents a list of Builder objects.
type BuilderList struct {
	*Value
}

// For iterates over the list of builders and calls f for each one.
// If f returns a non-nil error, iteration will stop and the error
// will be returned as the result of For.
func (list *BuilderList) For(f func(b *Builder) error) error {
	return list.Value.For(func(v *Value) error {
		return f(&Builder{v})
	})
}
