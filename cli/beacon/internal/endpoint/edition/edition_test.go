package edition

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const testKey = "bcn_device_abcd1234_secretpart"

var testSHA = strings.Repeat("ab", 32)

func platform(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func answer(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func TestLocateSendsTheDeviceKeyAndReadsTheRelease(t *testing.T) {
	var gotAuth, gotBody, gotPath string
	srv := platform(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		data, _ := io.ReadAll(r.Body)
		gotBody = string(data)
		answer(w, 200, map[string]any{
			"version": "1.3.41", "name": "BeaconEnterprise-1.3.41-arm64.pkg",
			"url": "https://release-assets.example/pkg?sig=x", "sha256": strings.ToUpper(testSHA), "size": 74725771,
		})
	})

	rel, err := Locate(context.Background(), nil, srv.URL+"/", testKey, "")
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if gotAuth != "Bearer "+testKey || gotPath != DownloadPath || gotBody != "{}" {
		t.Fatalf("request = %q %q %q", gotAuth, gotPath, gotBody)
	}
	want := Release{Version: "1.3.41", Name: "BeaconEnterprise-1.3.41-arm64.pkg",
		URL: "https://release-assets.example/pkg?sig=x", SHA256: testSHA, Size: 74725771}
	if rel != want {
		t.Fatalf("release = %+v", rel)
	}

	if _, err := Locate(context.Background(), nil, srv.URL, testKey, "v1.3.41"); err != nil {
		t.Fatalf("Locate with a version: %v", err)
	}
	if gotBody != `{"version":"1.3.41"}` {
		t.Fatalf("body = %q", gotBody)
	}
}

func TestLocateRefusesToSendTheKeyOverPlainHTTP(t *testing.T) {
	_, err := Locate(context.Background(), nil, "http://platform.example", testKey, "")
	if err == nil || !strings.Contains(err.Error(), "https is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestLocateNeverFollowsARedirect(t *testing.T) {
	var followed atomic.Bool
	elsewhere := platform(t, func(http.ResponseWriter, *http.Request) { followed.Store(true) })
	srv := platform(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+DownloadPath, http.StatusTemporaryRedirect)
	})
	_, err := Locate(context.Background(), nil, srv.URL, testKey, "")
	var refused *HTTPError
	if !errors.As(err, &refused) || refused.Status != http.StatusTemporaryRedirect {
		t.Fatalf("err = %v", err)
	}
	if followed.Load() {
		t.Fatal("the device key followed a redirect")
	}
}

func TestLocateReturnsThePlatformsRefusal(t *testing.T) {
	srv := platform(t, func(w http.ResponseWriter, _ *http.Request) {
		answer(w, 403, map[string]string{"detail": "policy enforcement is not enabled for this organization"})
	})
	_, err := Locate(context.Background(), nil, srv.URL, testKey, "")
	var refused *HTTPError
	if !errors.As(err, &refused) || refused.Status != 403 ||
		refused.Detail != "policy enforcement is not enabled for this organization" {
		t.Fatalf("err = %v", err)
	}
}

func TestLocateRejectsAnAnswerItCannotInstall(t *testing.T) {
	good := map[string]any{"version": "1.3.41", "url": "https://x.example/p", "sha256": testSHA, "size": 1}
	for name, tc := range map[string]struct {
		change  map[string]any
		version string
		want    string
	}{
		"no version":      {change: map[string]any{"version": "latest"}, want: "no release version"},
		"another version": {version: "1.3.40", want: "answered with 1.3.41"},
		"no checksum":     {change: map[string]any{"sha256": "abc"}, want: "no SHA-256"},
		"plain http link": {change: map[string]any{"url": "http://x.example/p"}, want: "no https download link"},
	} {
		t.Run(name, func(t *testing.T) {
			body := map[string]any{}
			for k, v := range good {
				body[k] = v
			}
			for k, v := range tc.change {
				body[k] = v
			}
			srv := platform(t, func(w http.ResponseWriter, _ *http.Request) { answer(w, 200, body) })
			_, err := Locate(context.Background(), nil, srv.URL, testKey, tc.version)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
