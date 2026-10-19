package release

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var oldSHA = strings.Repeat("a", 40)
var newSHA = strings.Repeat("b", 40)

const base = "/repos/owner/repo"

type call struct {
	method, path string
	payload      any
	binary       []byte
}
type fakeAPI struct {
	calls            []call
	ref              *reference
	comparison, head string
	releases         []release
	failUpload       bool
	override         map[string]any
}

func (f *fakeAPI) Request(_ context.Context, method, path string, payload any, binary []byte, _ bool) (json.RawMessage, error) {
	f.calls = append(f.calls, call{method, path, payload, append([]byte(nil), binary...)})
	if method == "GET" {
		if value, ok := f.override[path]; ok {
			return json.Marshal(value)
		}
		switch {
		case path == base+"/git/ref/tags/rolling":
			if f.ref == nil {
				return nil, nil
			}
			return json.Marshal(f.ref)
		case strings.Contains(path, "/compare/"):
			return json.Marshal(map[string]any{"status": f.comparison})
		case path == base+"/branches/master":
			return json.Marshal(map[string]any{"commit": map[string]string{"sha": f.head}})
		case strings.Contains(path, "/releases?per_page=100"):
			if f.releases == nil {
				return []byte("[]"), nil
			}
			return json.Marshal(f.releases)
		default:
			return nil, errors.New("unexpected GET")
		}
	}
	if strings.Contains(path, "/assets?name=") && f.failUpload {
		return nil, errors.New("upload failed")
	}
	if method == "POST" && path == base+"/releases" {
		return json.Marshal(release{ID: 7, TagName: tag})
	}
	return nil, nil
}
func (f *fakeAPI) writes() []call {
	var out []call
	for _, c := range f.calls {
		if c.method != "GET" {
			out = append(out, c)
		}
	}
	return out
}
func executable(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), assetName)
	if err := os.WriteFile(path, []byte("MZsynthetic tested EXE"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func existing() *fakeAPI {
	return &fakeAPI{ref: &reference{Object: object{Type: "commit", SHA: oldSHA}}, comparison: "ahead", releases: []release{{ID: 7, TagName: tag}}}
}
func publish(t *testing.T, f *fakeAPI) (bool, error) {
	t.Helper()
	return Publish(context.Background(), f, executable(t), "owner/repo", newSHA, "42")
}

func TestFirstPublicationDraftThenRawEXEThenTag(t *testing.T) {
	f := new(fakeAPI)
	ok, err := publish(t, f)
	if err != nil || !ok {
		t.Fatal(err)
	}
	w := f.writes()
	if len(w) != 4 {
		t.Fatal(w)
	}
	if w[0].path != base+"/releases" || w[0].payload.(map[string]any)["draft"] != true {
		t.Fatal("first release was not hidden")
	}
	if !strings.HasSuffix(w[1].path, "/assets?name=WarpPocket.exe") || !bytes.HasPrefix(w[1].binary, []byte("MZ")) {
		t.Fatal("not a raw EXE asset")
	}
	if w[2].path != base+"/git/refs" || w[2].payload.(map[string]any)["sha"] != newSHA {
		t.Fatal("tag was not created after upload")
	}
	final := w[3].payload.(map[string]any)
	if final["draft"] != false || final["make_latest"] != "true" || !strings.Contains(final["body"].(string), newSHA) {
		t.Fatal("release not finalized")
	}
}
func TestUpdateRemovesLegacyAssetsAndKeepsReleaseID(t *testing.T) {
	f := existing()
	f.releases[0].Assets = []asset{{1, assetName}, {2, "old.zip"}, {3, "WarpPocket.exe.sha256"}, {4, "summary.json"}}
	if ok, err := publish(t, f); err != nil || !ok {
		t.Fatal(err)
	}
	w := f.writes()
	if len(w) != 7 {
		t.Fatal(w)
	}
	if w[0].method != "DELETE" || !strings.HasSuffix(w[0].path, "/assets/1") || len(w[1].binary) == 0 {
		t.Fatal("wrong replacement order")
	}
	for _, i := range []int{2, 3, 4} {
		if w[i].method != "DELETE" {
			t.Fatal("legacy sidecar survived")
		}
	}
	if w[5].method != "PATCH" || w[5].payload.(map[string]any)["force"] != true || w[6].path != base+"/releases/7" {
		t.Fatal("wrong rolling update")
	}
}
func TestOlderBuildSkippedWithoutMutation(t *testing.T) {
	f := existing()
	f.comparison = "behind"
	ok, err := publish(t, f)
	if err != nil || ok || len(f.writes()) != 0 {
		t.Fatal(ok, err, f.writes())
	}
}
func TestIdenticalCommitMayBeRebuilt(t *testing.T) {
	f := existing()
	f.comparison = "identical"
	if ok, err := publish(t, f); err != nil || !ok {
		t.Fatal(err)
	}
}
func TestDivergedLineageRequiresCurrentMaster(t *testing.T) {
	for _, current := range []bool{false, true} {
		f := existing()
		f.comparison = "diverged"
		f.head = oldSHA
		if current {
			f.head = newSHA
		}
		ok, err := publish(t, f)
		if err != nil || ok != current || (!current && len(f.writes()) != 0) {
			t.Fatal(current, ok, err)
		}
	}
}
func TestAnnotatedTagResolvedAndCyclesRejected(t *testing.T) {
	f := existing()
	f.ref.Object.Type = "tag"
	f.override = map[string]any{base + "/git/tags/" + oldSHA: reference{Object: object{Type: "commit", SHA: oldSHA}}}
	if ok, err := publish(t, f); err != nil || !ok {
		t.Fatal(err)
	}
	f = existing()
	f.ref.Object.Type = "tag"
	f.override = map[string]any{base + "/git/tags/" + oldSHA: *f.ref}
	if _, err := publish(t, f); err == nil || len(f.writes()) != 0 {
		t.Fatal("cyclic tag accepted")
	}
}
func TestFailedFirstDraftResumed(t *testing.T) {
	f := &fakeAPI{releases: []release{{ID: 8, TagName: tag}}}
	if ok, err := publish(t, f); err != nil || !ok {
		t.Fatal(err)
	}
	for _, c := range f.writes() {
		if c.path == base+"/releases" {
			t.Fatal("created duplicate draft")
		}
	}
	if !strings.Contains(f.writes()[0].path, "/releases/8/") {
		t.Fatal("did not resume draft")
	}
}
func TestPaginatedDraftLookup(t *testing.T) {
	f := new(fakeAPI)
	first := make([]release, 100)
	for i := range first {
		first[i] = release{ID: int64(i + 100), TagName: "old"}
	}
	f.override = map[string]any{base + "/releases?per_page=100&page=1": first, base + "/releases?per_page=100&page=2": []release{{ID: 8, TagName: tag}}}
	if ok, err := publish(t, f); err != nil || !ok {
		t.Fatal(err)
	}
	if !strings.Contains(f.writes()[0].path, "/releases/8/") {
		t.Fatal("draft on second page not found")
	}
}
func TestInvalidBinaryAndContextMakeNoAPICalls(t *testing.T) {
	for _, name := range []string{"bundle.zip", assetName} {
		f := new(fakeAPI)
		path := filepath.Join(t.TempDir(), name)
		_ = os.WriteFile(path, []byte("not EXE"), 0600)
		if _, err := Publish(context.Background(), f, path, "owner/repo", newSHA, "42"); err == nil || len(f.calls) != 0 {
			t.Fatal("invalid executable reached API")
		}
	}
	f := new(fakeAPI)
	if _, err := Publish(context.Background(), f, executable(t), "bad/repo/other", newSHA, "42"); err == nil || len(f.calls) != 0 {
		t.Fatal("invalid context reached API")
	}
}
func TestImmutableReleaseNotMutated(t *testing.T) {
	f := existing()
	f.releases[0].Immutable = true
	if _, err := publish(t, f); err == nil || len(f.writes()) != 0 {
		t.Fatal("immutable release mutated")
	}
}
func TestUploadFailureDoesNotMoveTagOrPublishDraft(t *testing.T) {
	f := &fakeAPI{failUpload: true}
	if ok, err := publish(t, f); err == nil || ok {
		t.Fatal("failed upload accepted")
	}
	for _, c := range f.writes() {
		if strings.Contains(c.path, "/git/") || c.method == "PATCH" {
			t.Fatal("failed upload changed publication", c)
		}
	}
}
func TestCLIRefusesNonMasterBeforeTokenAccess(t *testing.T) {
	for _, context := range [][2]string{{"pull_request", "refs/heads/master"}, {"push", "refs/heads/other"}, {"workflow_dispatch", "refs/heads/master"}} {
		tokenRead := false
		env := func(name string) string {
			switch name {
			case "GITHUB_EVENT_NAME":
				return context[0]
			case "GITHUB_REF":
				return context[1]
			case "GITHUB_TOKEN":
				tokenRead = true
			}
			return ""
		}
		var output bytes.Buffer
		if Main([]string{"--exe", assetName}, env, &output, &output) == 0 || tokenRead {
			t.Fatal("untrusted event accessed publication token")
		}
	}
}
func TestRawUploadUsesOnlyUploadHost(t *testing.T) {
	apiCalls, uploadCalls := 0, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { apiCalls++; _, _ = w.Write([]byte(`{}`)) }))
	defer api.Close()
	upload := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadCalls++
		data, _ := io.ReadAll(r.Body)
		if string(data) != "MZtest" || r.Header.Get("Content-Type") != "application/vnd.microsoft.portable-executable" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("wrong authenticated binary upload")
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upload.Close()
	g := NewGitHub("test-token")
	g.apiRoot = api.URL
	g.uploadRoot = upload.URL
	if _, err := g.Request(context.Background(), "POST", "/asset", nil, []byte("MZtest"), false); err != nil {
		t.Fatal(err)
	}
	if apiCalls != 0 || uploadCalls != 1 {
		t.Fatal(apiCalls, uploadCalls)
	}
}
func TestOnlyOptionalGET404IsMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server-sensitive-text", http.StatusNotFound)
	}))
	defer server.Close()
	g := NewGitHub("test-token")
	g.apiRoot = server.URL
	if value, err := g.Request(context.Background(), "GET", "/optional", nil, nil, true); err != nil || value != nil {
		t.Fatal("optional absent ref not accepted")
	}
	for _, method := range []string{"GET", "POST"} {
		_, err := g.Request(context.Background(), method, "/required", nil, nil, method == "POST")
		if err == nil || strings.Contains(err.Error(), "server-sensitive") {
			t.Fatal("HTTP error suppressed or leaked")
		}
	}
}
func TestNoRedirectForwardsToken(t *testing.T) {
	forwarded := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded++; _, _ = w.Write([]byte(`{}`)) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer source.Close()
	g := NewGitHub("test-token")
	g.apiRoot = source.URL
	if _, err := g.Request(context.Background(), "GET", "/redirect", nil, nil, false); err == nil || forwarded != 0 {
		t.Fatal("authenticated redirect followed")
	}
}

type brokenTransport struct{}

func (brokenTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("test-token sensitive request")
}
func TestNetworkErrorsAreRedacted(t *testing.T) {
	g := NewGitHub("test-token")
	g.http.Transport = brokenTransport{}
	_, err := g.Request(context.Background(), "GET", "/anything", nil, nil, false)
	if err == nil || strings.Contains(err.Error(), "test-token") || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("network error leaked request data")
	}
}
