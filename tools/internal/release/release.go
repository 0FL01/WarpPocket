// Package release publishes exactly the tested EXE to the rolling release.
// The workflow serializes writers; commit comparison additionally prevents an
// older completed build from rolling back a newer publication.
package release

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const tag = "rolling"
const assetName = "WarpPocket.exe"

type API interface {
	Request(context.Context, string, string, any, []byte, bool) (json.RawMessage, error)
}

type GitHub struct {
	token, apiRoot, uploadRoot string
	http                       *http.Client
}

func NewGitHub(token string) *GitHub {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &GitHub{token: token, apiRoot: "https://api.github.com", uploadRoot: "https://uploads.github.com",
		http: &http.Client{Transport: transport, Timeout: 120 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (g *GitHub) Request(ctx context.Context, method, path string, payload any, binary []byte, optional bool) (json.RawMessage, error) {
	var data []byte
	root, contentType := g.apiRoot, "application/json"
	if binary != nil {
		data, root, contentType = binary, g.uploadRoot, "application/vnd.microsoft.portable-executable"
	} else if payload != nil {
		var err error
		data, err = json.Marshal(payload)
		if err != nil {
			return nil, errors.New("invalid API payload")
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, root+path, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("invalid API request")
	}
	request.Header.Set("Authorization", "Bearer "+g.token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("User-Agent", "WarpPocket-rolling-release")
	response, err := g.http.Do(request)
	if err != nil {
		return nil, errors.New("GitHub API connection failed")
	}
	defer response.Body.Close()
	if optional && method == http.MethodGet && response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(body) > 4<<20 {
		return nil, errors.New("invalid GitHub API response")
	}
	if len(body) > 0 && !json.Valid(body) {
		return nil, errors.New("invalid GitHub API response")
	}
	return body, nil
}

type object struct{ Type, SHA string }
type reference struct{ Object object }
type asset struct {
	ID   int64
	Name string
}
type release struct {
	ID        int64
	TagName   string `json:"tag_name"`
	Immutable bool
	Assets    []asset
}

func read[T any](ctx context.Context, api API, path string, optional bool) (*T, error) {
	raw, err := api.Request(ctx, http.MethodGet, path, nil, nil, optional)
	if err != nil || raw == nil {
		return nil, err
	}
	var value T
	if json.Unmarshal(raw, &value) != nil {
		return nil, errors.New("invalid GitHub API response")
	}
	return &value, nil
}

func findRolling(ctx context.Context, api API, base string) (*release, error) {
	for page := 1; ; page++ {
		releases, err := read[[]release](ctx, api, fmt.Sprintf("%s/releases?per_page=100&page=%d", base, page), false)
		if err != nil {
			return nil, err
		}
		if releases == nil {
			return nil, errors.New("missing releases response")
		}
		for _, r := range *releases {
			if r.TagName == tag {
				return &r, nil
			}
		}
		if len(*releases) < 100 {
			return nil, nil
		}
	}
}

func validSHA(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 20
}
func validRepository(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, c := range strings.Join(parts, "") {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func Publish(ctx context.Context, api API, executable, repository, sha, runID string) (bool, error) {
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 100<<20 || filepath.Base(executable) != assetName {
		return false, errors.New("expected the packaged WarpPocket.exe, not an archive")
	}
	binary, err := os.ReadFile(executable)
	if err != nil || !bytes.HasPrefix(binary, []byte("MZ")) {
		return false, errors.New("expected the packaged WarpPocket.exe, not an archive")
	}
	id, err := strconv.ParseUint(runID, 10, 64)
	if !validRepository(repository) || !validSHA(sha) || err != nil || id == 0 {
		return false, errors.New("invalid workflow context")
	}
	base := "/repos/" + repository
	ref, err := read[reference](ctx, api, base+"/git/ref/tags/"+tag, true)
	if err != nil {
		return false, err
	}
	if ref != nil {
		target := ref.Object
		seen := make(map[string]bool)
		for target.Type == "tag" {
			if !validSHA(target.SHA) || seen[target.SHA] {
				return false, errors.New("invalid annotated rolling tag")
			}
			seen[target.SHA] = true
			annotation, err := read[reference](ctx, api, base+"/git/tags/"+target.SHA, false)
			if err != nil {
				return false, err
			}
			if annotation == nil {
				return false, errors.New("missing annotated tag")
			}
			target = annotation.Object
		}
		if target.Type != "commit" || !validSHA(target.SHA) {
			return false, errors.New("rolling tag does not point to a commit")
		}
		comparison, err := read[struct{ Status string }](ctx, api, base+"/compare/"+target.SHA+"..."+sha, false)
		if err != nil {
			return false, err
		}
		if comparison == nil {
			return false, errors.New("missing commit comparison")
		}
		switch comparison.Status {
		case "behind":
			return false, nil
		case "ahead", "identical":
		case "diverged":
			head, err := read[struct{ Commit struct{ SHA string } }](ctx, api, base+"/branches/master", false)
			if err != nil {
				return false, err
			}
			if head == nil {
				return false, errors.New("missing branch head")
			}
			if head.Commit.SHA != sha {
				return false, nil
			}
		default:
			return false, errors.New("unexpected commit comparison status")
		}
	}
	r, err := findRolling(ctx, api, base)
	if err != nil {
		return false, err
	}
	if r == nil {
		raw, err := api.Request(ctx, http.MethodPost, base+"/releases", map[string]any{"tag_name": tag, "target_commitish": sha, "name": "Rolling release", "draft": true, "prerelease": false}, nil, false)
		if err != nil {
			return false, err
		}
		r = new(release)
		if json.Unmarshal(raw, r) != nil {
			return false, errors.New("invalid draft response")
		}
	}
	if r.Immutable {
		return false, errors.New("repository release immutability prevents a rolling release")
	}
	if r.ID <= 0 {
		return false, errors.New("invalid release identity")
	}
	mutate := func(method, path string, payload any, binary []byte) error {
		_, err := api.Request(ctx, method, path, payload, binary, false)
		return err
	}
	for _, old := range r.Assets {
		if old.Name == assetName {
			if err := mutate(http.MethodDelete, fmt.Sprintf("%s/releases/assets/%d", base, old.ID), nil, nil); err != nil {
				return false, err
			}
		}
	}
	if err := mutate(http.MethodPost, fmt.Sprintf("%s/releases/%d/assets?name=%s", base, r.ID, assetName), nil, binary); err != nil {
		return false, err
	}
	for _, old := range r.Assets {
		if old.Name != assetName {
			if err := mutate(http.MethodDelete, fmt.Sprintf("%s/releases/assets/%d", base, old.ID), nil, nil); err != nil {
				return false, err
			}
		}
	}
	if ref != nil {
		err = mutate(http.MethodPatch, base+"/git/refs/tags/"+tag, map[string]any{"sha": sha, "force": true}, nil)
	} else {
		err = mutate(http.MethodPost, base+"/git/refs", map[string]any{"ref": "refs/tags/" + tag, "sha": sha}, nil)
	}
	if err != nil {
		return false, err
	}
	body := fmt.Sprintf("Автоматическая rolling-сборка после успешных проверок push в `master`.\n\nКоммит: [%s](https://github.com/%s/commit/%s)\n\n[Workflow](https://github.com/%s/actions/runs/%s)\n\nСкачать и запустить `WarpPocket.exe`: нативный Go / Gio, без Python и извлекаемых helpers. Архивы, checksum-файлы и smoke-отчёты не публикуются в релизе.\n\nПриёмка на чистой Windows 10 пока не подтверждена; CI проверяет Windows Server 2022.", sha, repository, sha, repository, runID)
	err = mutate(http.MethodPatch, fmt.Sprintf("%s/releases/%d", base, r.ID), map[string]any{"tag_name": tag, "target_commitish": sha, "name": "Rolling release", "draft": false, "prerelease": false, "make_latest": "true", "body": body}, nil)
	return err == nil, err
}

func Main(args []string, env func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	executable := flags.String("exe", "", "tested WarpPocket.exe")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *executable == "" {
		fmt.Fprintln(stderr, "Rolling publication failed: --exe is required")
		return 1
	}
	if env("GITHUB_EVENT_NAME") != "push" || env("GITHUB_REF") != "refs/heads/master" {
		fmt.Fprintln(stderr, "Publication is allowed only for a push to master")
		return 1
	}
	token := env("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(stderr, "GITHUB_TOKEN is required")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	published, err := Publish(ctx, NewGitHub(token), *executable, env("GITHUB_REPOSITORY"), env("GITHUB_SHA"), env("GITHUB_RUN_ID"))
	if err != nil {
		fmt.Fprintln(stderr, "Rolling publication failed:", err)
		return 1
	}
	if published {
		fmt.Fprintln(stdout, "Published https://github.com/"+env("GITHUB_REPOSITORY")+"/releases/download/rolling/WarpPocket.exe")
	} else {
		fmt.Fprintln(stdout, "Skipping an older or superseded build.")
	}
	return 0
}
