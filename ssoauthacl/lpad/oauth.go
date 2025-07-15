package lpad

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The OAuth type enables authenticated sessions to be established with
// Launchpad using the oauth protocol.  See StoredOAuth and ConsoleOAuth
// for more features added on top of this type.
//
// For more details, see Launchpad's documentation on the subject:
//
//     https://help.launchpad.net/API/SigningRequests
//
type OAuth struct {
	BaseURL            string             // Defaults to https://(staging.)launchpad.net/
	AuthURL            string             // Set by Login before Callback is called
	Callback           func(*OAuth) error // Called by Login to get user to AuthURL
	CallbackURL        string             // Optional. AuthURL will redirect here after confirmation
	Token, TokenSecret string             // Credentials obtained
	Consumer           string             // Consumer name. Defaults to "https://launchpad.net/lpad"
	Anonymous          bool               // Don't try to login
}

func (oauth *OAuth) consumer() string {
	if oauth.Consumer == "" {
		return "https://launchpad.net/lpad"
	}
	return oauth.Consumer
}

func (oauth *OAuth) requestToken(path string, form url.Values) (err error) {
	r, err := http.PostForm(oauth.BaseURL+path, form)
	if err != nil {
		return
	}
	data, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return
	}
	query, err := url.ParseQuery(string(data))
	if err != nil {
		return
	}

	token, ok := query["oauth_token"]
	if !ok || len(token) == 0 {
		return errors.New("oauth_token missing from " + path + " response: " + string(data))
	}

	secret, ok := query["oauth_token_secret"]
	if !ok || len(secret) == 0 {
		return errors.New("oauth_token_secret missing from " + path + " response: " + string(data))
	}

	oauth.Token = token[0]
	oauth.TokenSecret = secret[0]
	return
}

func (oauth *OAuth) Login(baseURL string) error {
	if oauth.BaseURL == "" {
		url, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		// https://api.launchpad.net/1.0/ => https://launchpad.net/
		if strings.HasPrefix(url.Host, "api.") {
			url.Host = url.Host[4:]
		}
		url.Path = ""
		oauth.BaseURL = url.String()
	}
	if oauth.BaseURL[len(oauth.BaseURL)-1] == '/' {
		oauth.BaseURL = oauth.BaseURL[:len(oauth.BaseURL)-1]
	}

	if oauth.Anonymous || oauth.TokenSecret != "" && oauth.AuthURL == "" {
		return nil // Ready to sign.
	}

	form := url.Values{
		"oauth_consumer_key":     []string{oauth.consumer()},
		"oauth_signature_method": []string{"PLAINTEXT"},
		"oauth_signature":        []string{"&"},
	}
	if err := oauth.requestToken("/+request-token", form); err != nil {
		return err
	}

	authQuery := url.Values{}
	authQuery["oauth_token"] = []string{oauth.Token}
	if oauth.CallbackURL != "" {
		authQuery["oauth_callback"] = []string{oauth.CallbackURL}
	}

	oauth.AuthURL = oauth.BaseURL + "/+authorize-token?" + authQuery.Encode()

	if oauth.Callback != nil {
		if err := oauth.Callback(oauth); err != nil {
			return err
		}
	}

	form["oauth_token"] = []string{oauth.Token}
	form["oauth_signature"] = []string{"&" + oauth.TokenSecret}

	if err := oauth.requestToken("/+access-token", form); err != nil {
		return err
	}

	oauth.AuthURL = ""
	return nil
}

func (oauth *OAuth) Sign(req *http.Request) error {
	if !oauth.Anonymous {
		if oauth.Token == "" {
			return errors.New("OAuth can't Sign without a token (missing Login?)")
		}
		if oauth.TokenSecret == "" {
			return errors.New("OAuth can't Sign without a token secret (missing Login?)")
		}
	}
	auth := `OAuth realm="https://api.launchpad.net/", ` +
		`oauth_consumer_key="` + url.QueryEscape(oauth.consumer()) + `", ` +
		`oauth_token="` + url.QueryEscape(oauth.Token) + `", ` +
		`oauth_signature_method="PLAINTEXT", ` +
		`oauth_signature="` + url.QueryEscape(`&`+oauth.TokenSecret) + `", ` +
		`oauth_timestamp="` + strconv.FormatInt(time.Now().Unix(), 10) + `", ` +
		`oauth_nonce="` + strconv.Itoa(int(rand.Int31())) + `", ` +
		`oauth_version="1.0"`
	req.Header.Add("Authorization", auth)
	return nil
}

// The StoredOAuth type behaves like OAuth, but will cache a successful
// authentication in ~/.lpad_oauth and reuse it in future Login requests.
//
// See the OAuth type for details on how to construct values of this type,
// and see the Login method for a convenient way to make use of them.
type StoredOAuth OAuth

// We might use an embedded type to avoid wrapping the methods, but that
// would prevent people from building StoredOAuth values with explicit
// fields such as StoredOAuth{Callback: ...}.

type oauthDump struct {
	Token, TokenSecret string
}

func (oauth *StoredOAuth) Login(baseURL string) error {
	if oauth.TokenSecret == "" && oauth.read() == nil {
		return nil
	}
	err := (*OAuth)(oauth).Login(baseURL)
	if err != nil {
		return err
	}
	return oauth.write()
}

func (oauth *StoredOAuth) Sign(req *http.Request) error {
	return (*OAuth)(oauth).Sign(req)
}

func (oauth *StoredOAuth) read() error {
	path := os.ExpandEnv("$HOME/.lpad_oauth")
	if oauth.TokenSecret != "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	data, err := ioutil.ReadAll(file)
	file.Close()
	if err != nil {
		return err
	}
	dump := &oauthDump{}
	err = json.Unmarshal(data, dump)
	if err != nil {
		return err
	}
	oauth.Token = dump.Token
	oauth.TokenSecret = dump.TokenSecret
	return nil
}

func (oauth *StoredOAuth) write() error {
	path := os.ExpandEnv("$HOME/.lpad_oauth")
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := json.Marshal(&oauthDump{oauth.Token, oauth.TokenSecret})
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	return err
}

// The ConsoleOAuth type will cache successful authentications like
// StoredOAuth and will also open a browser for the user to confirm
// authentication and wait for confirmation with a console message
// on standard output.
//
// See the OAuth type for details on how to construct values of this type,
// and see the Login method for a convenient way to make use of them.
type ConsoleOAuth StoredOAuth

// We might use an embedded type to avoid wrapping the methods, but that
// would prevent people from building ConsoleOAuth values with explicit
// fields such as ConsoleOAuth{Callback: ...}.

func (oauth *ConsoleOAuth) Login(baseURL string) error {
	oauth.Callback = fireBrowser
	err := (*StoredOAuth)(oauth).Login(baseURL)
	if err != nil {
		return err
	}
	return nil
}

func (oauth *ConsoleOAuth) Sign(req *http.Request) error {
	return (*StoredOAuth)(oauth).Sign(req)
}

func fireBrowser(oauth *OAuth) error {
	browser, err := findBrowser()
	if err == nil {
		args := []string{browser, oauth.AuthURL}
		p, err := os.StartProcess(args[0], args, &os.ProcAttr{})
		if err == nil {
			go func() { p.Wait() }() // Avoid zombies.
		} else {
			browser = ""
		}
	}
	if browser != "" {
		fmt.Printf("Go to your browser now and authorize access to Launchpad.\n")
	} else {
		fmt.Printf("Open the following URL in your browser:\n    %s\n", oauth.AuthURL)
	}
	fmt.Printf("Press [ENTER] after authorization is confirmed... ")
	b := make([]byte, 1)
	os.Stdin.Read(b)
	return nil
}

func findBrowser() (path string, err error) {
	path, err = exec.LookPath("sensible-browser")
	if err == nil {
		return path, nil
	}
	browser := os.Getenv("BROWSER")
	if browser == "" {
		return "", err
	}
	return exec.LookPath(browser)
}
