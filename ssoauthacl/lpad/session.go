// This simple example demonstrates how to get started using lpad to
// communicate with Launchpad in a console application:
//
//     root, err := lpad.Login(lpad.Production, &lpad.ConsoleOAuth{})
//     if err != nil {
//         panic(err)
//     }
//     me, err := root.Me()
//     if err != nil {
//         panic(err)
//     }
//     fmt.Println(me.DisplayName())
//
package lpad

import "net/http"

// The Auth interface is implemented by types which are able to Login and
// authenticate requests made against Launchpad.
type Auth interface {
	Login(baseURL string) (err error)
	Sign(req *http.Request) (err error)
}

type APIBase string

const (
	Production APIBase = "https://api.launchpad.net/devel/"
	Staging    APIBase = "https://api.staging.launchpad.net/devel/"
)

// The Session type represents a session of communication with Launchpad,
// and carries the authenticator necessary to validate requests in the
// given session.  Creating sessions explicitly is generally not necessary.
// See the Login method for a convenient way to use lpad to access the
// Launchpad API.
type Session struct {
	auth Auth
}

// Create a new session using the auth authenticator.  Creating sessions
// explicitly is generally not necessary.  See the Login method for a
// convenient way to use lpad to access the Launchpad API.
func NewSession(auth Auth) *Session {
	return &Session{auth}
}

func (s *Session) Sign(req *http.Request) (err error) {
	return s.auth.Sign(req)
}

// Login returns a Root object with a new session authenticated in Launchpad
// using the auth authenticator. This is the primary method to start using
// the Launchpad API.
//
// This simple example demonstrates how to get a user's name in a console
// application:
//
//     oauth := &lpad.ConsoleOAuth{Consumer: "your-app"}
//     root, err := lpad.Login(lpad.Production, oauth)
//     check(err)
//     me, err := root.Me()
//     check(err)
//     fmt.Println(me.DisplayName())
//
// Alternatively, it is possible to communicate with Launchpad anonymously:
//
//     oauth := &lpad.ConsoleOAuth{Consumer: "your-app", Anonymous: true}
//     root, err := lpad.Login(lpad.Production, oauth)
//     check(err)
//
func Login(baseurl APIBase, auth Auth) (*Root, error) {
	baseloc := string(baseurl)
	if err := auth.Login(baseloc); err != nil {
		return nil, err
	}
	return &Root{&Value{session: NewSession(auth), baseloc: baseloc, loc: baseloc}}, nil
}
