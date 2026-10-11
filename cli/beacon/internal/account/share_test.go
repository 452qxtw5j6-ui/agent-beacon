package account

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

const shareTestToken = "bcn_cli_share_secret"

func shareCred(baseURL string) ShareCredential {
	return ShareCredential{BaseURL: baseURL, Token: shareTestToken, Source: CredentialSourceLogin, User: User{ID: "u", Email: "dev@example.com"}}
}

func TestResolveShareCredentialPrecedence(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	good := &Session{BaseURL: "https://beacon.sh", AccessToken: "bcn_cli_x", Scopes: []string{ScopeTracesWrite}, User: User{ID: "u", Email: "e@x"}, ExpiresAt: now.Add(time.Hour)}
	stale := &Session{BaseURL: "https://beacon.sh", AccessToken: "bcn_cli_x", Scopes: []string{ScopeProfileRead}, User: User{ID: "u", Email: "e@x"}}
	expired := &Session{BaseURL: "https://beacon.sh", AccessToken: "bcn_cli_x", Scopes: []string{ScopeTracesWrite}, User: User{ID: "u", Email: "e@x"}, ExpiresAt: now.Add(-time.Hour)}
	load := func(s *Session, err error) func() (*Session, error) {
		return func() (*Session, error) { return s, err }
	}
	env := func(value string) func(string) string {
		return func(name string) string {
			if name == APIKeyEnv {
				return value
			}
			return ""
		}
	}
	cases := []struct {
		name       string
		opts       ResolveShareCredentialOptions
		wantSource string
		wantErr    error
		errText    string
	}{
		{"flag beats login", ResolveShareCredentialOptions{Key: "bcn_api_flag", Load: load(good, nil), Getenv: env("bcn_api_env")}, CredentialSourceFlag, nil, ""},
		{"login beats env", ResolveShareCredentialOptions{Load: load(good, nil), Getenv: env("bcn_api_env")}, CredentialSourceLogin, nil, ""},
		{"env when signed out", ResolveShareCredentialOptions{Load: load(nil, ErrNotSignedIn), Getenv: env("bcn_api_env")}, CredentialSourceEnv, nil, ""},
		{"env when the login lacks the scope", ResolveShareCredentialOptions{Load: load(stale, nil), Getenv: env("bcn_api_env")}, CredentialSourceEnv, nil, ""},
		{"older login without env", ResolveShareCredentialOptions{Load: load(stale, nil), Getenv: env("")}, "", ErrTracesWriteScope, ""},
		{"expired login", ResolveShareCredentialOptions{Load: load(expired, nil)}, "", nil, "expired"},
		{"nothing", ResolveShareCredentialOptions{Load: load(nil, ErrNotSignedIn)}, "", ErrNoShareCredential, ""},
		{"bad key", ResolveShareCredentialOptions{Key: "sk-something", Load: load(good, nil)}, "", nil, "not a Beacon API key"},
		{"login for the named service", ResolveShareCredentialOptions{BaseURL: "https://beacon.sh/", Load: load(good, nil)}, CredentialSourceLogin, nil, ""},
		{"login for another service is not used", ResolveShareCredentialOptions{BaseURL: "https://staging.beacon.sh", Load: load(good, nil)}, "", nil, "signed in to https://beacon.sh, not https://staging.beacon.sh"},
		{"env key for another service", ResolveShareCredentialOptions{BaseURL: "https://staging.beacon.sh", Load: load(good, nil), Getenv: env("bcn_api_env")}, CredentialSourceEnv, nil, ""},
		{"service named by the environment", ResolveShareCredentialOptions{Load: load(good, nil), Getenv: func(name string) string {
			if name == BaseURLEnv {
				return "https://staging.beacon.sh"
			}
			return ""
		}}, "", nil, "not https://staging.beacon.sh"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Now = now
			cred, err := ResolveShareCredential(tc.opts)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			case tc.errText != "":
				if err == nil || !strings.Contains(err.Error(), tc.errText) {
					t.Fatalf("err = %v, want %q", err, tc.errText)
				}
				if strings.Contains(err.Error(), "sk-something") {
					t.Fatalf("the rejected key was echoed: %v", err)
				}
				return
			case err != nil:
				t.Fatalf("err = %v", err)
			}
			if cred.Source != tc.wantSource {
				t.Fatalf("source = %q, want %q", cred.Source, tc.wantSource)
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v %s", cred, cred, cred, cred), cred.Token) {
				t.Fatal("formatting a credential prints its token")
			}
		})
	}
}

func TestShareClientRefusesInsecureURL(t *testing.T) {
	if _, err := NewShareClient(ShareCredential{BaseURL: "http://beacon.example.com", Token: "x"}, nil); err == nil {
		t.Fatal("expected an error for a non-loopback http URL")
	}
}

type shareServer struct {
	mu       sync.Mutex
	server   *httptest.Server
	auth     []string
	batches  [][]asymptoteobserve.ShareMessageV1
	encoding []string
	trace    *asymptoteobserve.ShareTraceV1
	paths    []string
}

func newShareServer(t *testing.T) *shareServer {
	s := &shareServer{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		s.paths = append(s.paths, r.Method+" "+r.URL.EscapedPath())
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/v1/traces/claude_code:abc":
			var trace asymptoteobserve.ShareTraceV1
			if err := json.NewDecoder(r.Body).Decode(&trace); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			s.trace = &trace
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":"k3x","external_id":"claude_code:abc","url":"https://beacon.sh/s/k3x","visibility":"direct","message_count":0,"created":true}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/traces/claude_code:abc/messages/batch":
			s.encoding = append(s.encoding, r.Header.Get("Content-Encoding"))
			var body io.Reader = r.Body
			if r.Header.Get("Content-Encoding") == "gzip" {
				zr, err := gzip.NewReader(r.Body)
				if err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				body = zr
			}
			var batch asymptoteobserve.ShareMessagesBatchV1
			if err := json.NewDecoder(body).Decode(&batch); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			s.batches = append(s.batches, batch.Messages)
			total := 0
			for _, b := range s.batches {
				total += len(b)
			}
			fmt.Fprintf(w, `{"accepted":%d,"message_count":%d}`, len(batch.Messages), total)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/traces/claude_code:abc":
			fmt.Fprint(w, `{"id":"k3x","url":"https://beacon.sh/s/k3x","visibility":"direct","message_count":2,"last_message_id":"m2","max_order":2}`)
		default:
			http.Error(w, `{"detail":"no such trace"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func messagesN(n int, textBytes int) []asymptoteobserve.ShareMessageV1 {
	out := make([]asymptoteobserve.ShareMessageV1, n)
	for i := range out {
		out[i] = asymptoteobserve.ShareMessageV1{
			ID: fmt.Sprintf("m%d", i+1), Order: i + 1, Role: "user", Timestamp: "2026-10-01T00:00:00Z",
			Text:  strings.Repeat("x", textBytes),
			Parts: []asymptoteobserve.SharePartV1{{Type: "text", Order: 1, Content: asymptoteobserve.ShareTextContent{Text: "x"}}},
		}
	}
	return out
}

func TestShareClientPutGetAndBatches(t *testing.T) {
	s := newShareServer(t)
	client, err := NewShareClient(shareCred(s.server.URL), s.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	result, err := client.PutTrace(ctx, "claude_code:abc", asymptoteobserve.ShareTraceV1{AgentID: "claude_code", Visibility: "direct"})
	if err != nil {
		t.Fatalf("PutTrace: %v", err)
	}
	if result.ID != "k3x" || !result.Created || s.trace.SchemaVersion != asymptoteobserve.ShareSchemaVersion {
		t.Fatalf("result = %+v trace = %+v", result, s.trace)
	}

	put, err := client.PutMessages(ctx, "claude_code:abc", messagesN(2500, 10))
	if err != nil {
		t.Fatalf("PutMessages: %v", err)
	}
	if put.Batches != 3 || put.Accepted != 2500 || put.MessageCount != 2500 {
		t.Fatalf("put = %+v", put)
	}
	if len(s.batches[0]) != 1000 || len(s.batches[2]) != 500 || s.batches[2][499].ID != "m2500" {
		t.Fatalf("batch sizes = %d %d %d", len(s.batches[0]), len(s.batches[1]), len(s.batches[2]))
	}
	for _, encoding := range s.encoding {
		if encoding != "gzip" {
			t.Fatalf("batch sent with Content-Encoding %q", encoding)
		}
	}

	state, found, err := client.GetTrace(ctx, "claude_code:abc")
	if err != nil || !found || state.LastMessageID != "m2" || state.MaxOrder != 2 {
		t.Fatalf("GetTrace = %+v %v %v", state, found, err)
	}
	if _, found, err := client.GetTrace(ctx, "claude_code:missing"); err != nil || found {
		t.Fatalf("missing trace: found=%v err=%v", found, err)
	}
	for _, auth := range s.auth {
		if auth != "Bearer "+shareTestToken {
			t.Fatalf("authorization = %q", auth)
		}
	}
	if _, err := client.PutMessages(ctx, "bad id!", messagesN(1, 1)); err == nil {
		t.Fatal("expected an invalid external id to be refused")
	}
}

func TestShareBatchesHonorTheByteLimit(t *testing.T) {
	batches, err := ShareBatches(messagesN(10, 1000), 1000, 3500)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, b := range batches {
		if len(b.Body) > 3500 {
			t.Fatalf("batch of %d bytes exceeds the limit", len(b.Body))
		}
		var decoded asymptoteobserve.ShareMessagesBatchV1
		if err := json.Unmarshal(b.Body, &decoded); err != nil || len(decoded.Messages) != b.Messages {
			t.Fatalf("batch does not decode: %v", err)
		}
		total += b.Messages
	}
	if total != 10 || len(batches) < 4 {
		t.Fatalf("batches = %d, messages = %d", len(batches), total)
	}
	if _, err := ShareBatches(messagesN(1, 5000), 1000, 3500); err == nil {
		t.Fatal("expected an oversized message to be refused")
	}
	if batches, err := ShareBatches(nil, 1000, 3500); err != nil || len(batches) != 0 {
		t.Fatalf("empty input = %v %v", batches, err)
	}
}

func TestShareClientRefusesRedirects(t *testing.T) {
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, err := NewShareClient(shareCred(redirect.URL), redirect.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PutTrace(context.Background(), "claude_code:abc", asymptoteobserve.ShareTraceV1{AgentID: "claude_code"})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v", err)
	}
	if followed {
		t.Fatal("the redirect was followed with the credential")
	}
}

func TestShareClientMapsAuthFailures(t *testing.T) {
	for _, tc := range []struct {
		status int
		source string
		want   string
		is     error
	}{
		{http.StatusUnauthorized, CredentialSourceLogin, "run `beacon login` again", nil},
		{http.StatusForbidden, CredentialSourceLogin, "", ErrTracesWriteScope},
		{http.StatusUnauthorized, CredentialSourceFlag, "rejected the API key from --key", nil},
		{http.StatusForbidden, CredentialSourceEnv, "needs the traces:write scope", nil},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			// A server echoing the credential back must not get it into the error.
			fmt.Fprintf(w, `{"detail":"bad token %s"}`, shareTestToken)
		}))
		cred := shareCred(server.URL)
		cred.Source = tc.source
		client, err := NewShareClient(cred, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.PutTrace(context.Background(), "claude_code:abc", asymptoteobserve.ShareTraceV1{AgentID: "claude_code"})
		server.Close()
		if err == nil {
			t.Fatalf("%d/%s: expected an error", tc.status, tc.source)
		}
		if tc.is != nil && !errors.Is(err, tc.is) {
			t.Fatalf("%d/%s: err = %v, want %v", tc.status, tc.source, err, tc.is)
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%d/%s: err = %v, want %q", tc.status, tc.source, err, tc.want)
		}
		if strings.Contains(err.Error(), shareTestToken) {
			t.Fatalf("%d/%s: the token reached the error: %v", tc.status, tc.source, err)
		}
	}
}
