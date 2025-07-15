package lpad_test

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	. "launchpad.net/gocheck"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

func Test(t *testing.T) {
	TestingT(t)
}

var integration = flag.Bool("i", false, "Enable integration tests")

type SuiteI struct{}

func (s *SuiteI) SetUpSuite(c *C) {
	if !*integration {
		c.Skip("Integration tests not enabled (-i flag)")
	}
}

type HTTPSuite struct{}

var testServer = NewTestHTTPServer("http://localhost:4444", 5 * time.Second)

func (s *HTTPSuite) SetUpSuite(c *C) {
	testServer.Start()
}

func (s *HTTPSuite) TearDownTest(c *C) {
	testServer.Flush()
}

type TestHTTPServer struct {
	URL      string
	Timeout  time.Duration
	started  bool
	request  chan *http.Request
	response chan *testResponse
	pending  chan bool
}

type testResponse struct {
	Status  int
	Headers map[string]string
	Body    string
}

func NewTestHTTPServer(url_ string, timeout time.Duration) *TestHTTPServer {
	return &TestHTTPServer{URL: url_, Timeout: timeout}
}

func (s *TestHTTPServer) Start() {
	if s.started {
		return
	}
	s.started = true

	s.request = make(chan *http.Request, 64)
	s.response = make(chan *testResponse, 64)
	s.pending = make(chan bool, 64)

	url_, _ := url.Parse(s.URL)
	go http.ListenAndServe(url_.Host, s)

	s.PrepareResponse(203, nil, "")
	for {
		// Wait for it to be up.
		resp, err := http.Get(s.URL)
		if err == nil && resp.StatusCode == 203 {
			break
		}
		fmt.Fprintf(os.Stderr, "\nWaiting for fake server to be up... ")
		time.Sleep(1e8)
	}
	fmt.Fprintf(os.Stderr, "done\n\n")
	s.WaitRequest() // Consume dummy request.
}

// FlushRequests discards requests which were not yet consumed by WaitRequest.
func (s *TestHTTPServer) Flush() {
	for {
		select {
		case <-s.request:
		case <-s.response:
		default:
			return
		}
	}
}

func body(req *http.Request) string {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func (s *TestHTTPServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}
	s.request <- req
	var resp *testResponse
	select {
	case resp = <-s.response:
	case <-time.After(s.Timeout):
		fmt.Fprintf(os.Stderr, "ERROR: Timeout waiting for test to provide response\n")
		resp = &testResponse{500, nil, ""}
	}
	if resp.Headers != nil {
		h := w.Header()
		for k, v := range resp.Headers {
			h.Set(k, v)
		}
	}
	if resp.Status != 0 {
		w.WriteHeader(resp.Status)
	}
	w.Write([]byte(resp.Body))
	// WriteHeader consumes the body per RFC2616. Restore it.
	req.Body = ioutil.NopCloser(bytes.NewBuffer(data))
}

func (s *TestHTTPServer) WaitRequest() *http.Request {
	select {
	case req := <-s.request:
		return req
	case <-time.After(s.Timeout):
		panic("Timeout waiting for request")
	}
	panic("unreached")
}

func (s *TestHTTPServer) PrepareResponse(status int, headers map[string]string, body string) {
	s.response <- &testResponse{status, headers, body}
}
