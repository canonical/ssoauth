package lpad

import (
	"net/url"
)

// The Root type provides the entrance for the Launchpad API.
type Root struct {
	*Value
}

// Me returns the Person authenticated into Lauchpad in the current session.
func (root *Root) Me() (*Person, error) {
	me, err := root.Location("/people/+me").Get(nil)
	if err != nil {
		return nil, err
	}
	return &Person{me}, nil
}

// Member returns the Team or Person with the provided name or username.
func (root *Root) Member(name string) (Member, error) {
	v, err := root.Location("/~" + url.QueryEscape(name)).Get(nil)
	if err != nil {
		return nil, err
	}
	if v.BoolField("is_team") {
		return &Team{v}, nil
	}
	return &Person{v}, nil
}

// FindPeople returns a PersonList containing all Person accounts whose
// Name, DisplayName or email address match text.
func (root *Root) FindPeople(text string) (*PersonList, error) {
	v, err := root.Location("/people").Get(Params{"ws.op": "findPerson", "text": text})
	if err != nil {
		return nil, err
	}
	return &PersonList{v}, nil
}

// FindTeams returns a TeamList containing all Team accounts whose
// Name, DisplayName or email address match text.
func (root *Root) FindTeams(text string) (*TeamList, error) {
	v, err := root.Location("/people").Get(Params{"ws.op": "findTeam", "text": text})
	if err != nil {
		return nil, err
	}
	return &TeamList{v}, nil
}

// FindMembers returns a MemberList containing all Person or Team accounts
// whose Name, DisplayName or email address match text.
func (root *Root) FindMembers(text string) (*MemberList, error) {
	v, err := root.Location("/people").Get(Params{"ws.op": "find", "text": text})
	if err != nil {
		return nil, err
	}
	return &MemberList{v}, nil
}

// The MemberList type encapsulates a mixed list containing Person and Team
// elements for iteration.
type MemberList struct {
	*Value
}

// For iterates over the list of people and teams and calls f for each one.
// If f returns a non-nil error, iteration will stop and the error will be
// returned as the result of For.
func (list *MemberList) For(f func(v Member) error) error {
	return list.Value.For(func(v *Value) error {
		if v.BoolField("is_team") {
			return f(&Team{v})
		}
		return f(&Person{v})
	})
}

// The PersonList type encapsulates a list of Person elements for iteration.
type PersonList struct {
	*Value
}

// For iterates over the list of people and calls f for each one.  If f
// returns a non-nil error, iteration will stop and the error will be
// returned as the result of For.
func (list *PersonList) For(f func(p *Person) error) error {
	return list.Value.For(func(v *Value) error {
		return f(&Person{v})
	})
}

// The TeamList type encapsulates a list of Team elements for iteration.
type TeamList struct {
	*Value
}

// For iterates over the list of teams and calls f for each one.  If f
// returns a non-nil error, iteration will stop and the error will be
// returned as the result of For.
func (list *TeamList) For(f func(t *Team) error) error {
	return list.Value.For(func(v *Value) error {
		return f(&Team{v})
	})
}

// Member is an interface implemented by both Person and Team.
type Member interface {
	AnyValue

	DisplayName() string
	SetDisplayName(name string)
	Name() string
	SetName(name string)
	WebPage() string

	// Member is a marker function for types satisfying the
	// the Member interface. This is necessary for now because 
	// the methods above are fairly common across several types,
	// but this will likely be dropped in the future.
	Member()
}

// The Person type represents a person in Launchpad.
type Person struct {
	*Value
}

var _ Member = (*Person)(nil)

// Member is a marker method so Person satisfies the Member interface.
func (person *Person) Member() {}

// DisplayName returns the person's name as it would be displayed
// throughout Launchpad.  Most people use their full name.
func (person *Person) DisplayName() string {
	return person.StringField("display_name")
}

// SetDisplayName changes the person's name as it would be displayed
// throughout Launchpad.  Most people use their full name.
// Patch must be called to commit all changes.
func (person *Person) SetDisplayName(name string) {
	person.SetField("display_name", name)
}

// Name returns the person's short unique name, beginning with a
// lower-case letter or number, and containing only letters, numbers,
// dots, hyphens, or plus signs.
func (person *Person) Name() string {
	return person.StringField("name")
}

// SetName changes the person's short unique name.
// The name must begin with a lower-case letter or number, and
// contain only letters, numbers, dots, hyphens, or plus signs.
func (person *Person) SetName(name string) {
	person.SetField("name", name)
}

// WebPage returns the URL for accessing this person's page in a browser.
func (person *Person) WebPage() string {
	return person.StringField("web_link")
}

// PreferredEmail returns the Person's preferred email. If the user
// disabled public access to email addresses, this method returns an
// *Error with StatusCode of 404.
func (person *Person) PreferredEmail() (string, error) {
	// WTF.. seriously!?
	e, err := person.Link("preferred_email_address_link").Get(nil)
	if err != nil {
		return "", err
	}
	return e.StringField("email"), nil
}

// IRCNicks returns a list of all IRC nicks for the person.
func (person *Person) IRCNicks() (nicks []*IRCNick, err error) {
	list, err := person.Link("irc_nicknames_collection_link").Get(nil)
	if err != nil {
		return nil, err
	}
	list.For(func(v *Value) error {
		nicks = append(nicks, &IRCNick{v})
		return nil
	})
	return
}

type IRCNick struct {
	*Value
}

// Nick returns the person's nick on an IRC network.
func (nick *IRCNick) Nick() string {
	return nick.StringField("nickname")
}

// SetNick changes the person's nick on an IRC network.
// Patch must be called to commit all changes.
func (nick *IRCNick) SetNick(n string) {
	nick.SetField("nickname", n)
}

// Network returns the IRC network this nick is associated to.
func (nick *IRCNick) Network() string {
	return nick.StringField("network")
}

// SetNetwork changes the IRC network this nick is associated to.
// Patch must be called to commit all changes.
func (nick *IRCNick) SetNetwork(n string) {
	nick.SetField("network", n)
}

// The Team type encapsulates access to details about a team in Launchpad.
type Team struct {
	*Value
}

var _ Member = (*Team)(nil)

// Member is a marker method so Team satisfies the Member interface.
func (team *Team) Member() {}

// Name returns the team's name.  This is a short unique name, beginning with a
// lower-case letter or number, and containing only letters, numbers, dots,
// hyphens, or plus signs.
func (team *Team) Name() string {
	return team.StringField("name")
}

// SetName changes the team's name.  This is a short unique name, beginning
// with a lower-case letter or number, and containing only letters, numbers,
// dots, hyphens, or plus signs.  Patch must be called to commit all changes.
func (team *Team) SetName(name string) {
	team.SetField("name", name)
}

// DisplayName returns the team's name as it would be displayed
// throughout Launchpad.
func (team *Team) DisplayName() string {
	return team.StringField("display_name")
}

// SetDisplayName changes the team's name as it would be displayed
// throughout Launchpad.  Patch must be called to commit all changes.
func (team *Team) SetDisplayName(name string) {
	team.SetField("display_name", name)
}

// WebPage returns the URL for accessing this team's page in a browser.
func (team *Team) WebPage() string {
	return team.StringField("web_link")
}
