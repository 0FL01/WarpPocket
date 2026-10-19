#!/usr/bin/env python3
"""Replace the rolling release with the tested EXE from a master push.

The workflow serializes this job. The tag comparison additionally prevents an
older build which finishes later from rolling the release back. Only the EXE
is a release asset; Actions' transport archive is never published.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

TAG = "rolling"
ASSET = "WarpPocket.exe"


class ReleaseError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward the publication token to a redirect target.


class GitHub:
    def __init__(self, token: str):
        self.token = token
        self.opener = build_opener(NoRedirect())

    def request(self, method: str, path: str, *, payload=None, binary=None, missing_ok=False):
        root = "https://uploads.github.com" if binary is not None else "https://api.github.com"
        data = binary if binary is not None else (
            json.dumps(payload).encode("utf-8") if payload is not None else None
        )
        request = Request(root + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/vnd.microsoft.portable-executable"
            if binary is not None else "application/json",
            "User-Agent": "WarpPocket-rolling-release",
        })
        try:
            with self.opener.open(request, timeout=120) as response:
                body = response.read()
        except HTTPError as error:
            if missing_ok and method == "GET" and error.code == 404:
                return None
            raise ReleaseError(f"GitHub API returned HTTP {error.code}") from None
        except URLError:
            raise ReleaseError("GitHub API connection failed") from None
        return json.loads(body) if body else None


def rolling_release(api, base: str):
    # GET /releases/tags/{tag} does not find drafts left by a failed first
    # publication. Listing also lets the next successful push resume that draft.
    page = 1
    while True:
        releases = api.request("GET", base + f"/releases?per_page=100&page={page}")
        for release in releases:
            if release["tag_name"] == TAG:
                return release
        if len(releases) < 100:
            return None
        page += 1


def publish(api, executable: Path, *, repository: str, sha: str, run_id: str) -> bool:
    binary = executable.read_bytes()
    if executable.name != ASSET or not binary.startswith(b"MZ"):
        raise ReleaseError("Expected the packaged WarpPocket.exe, not an archive")

    base = f"/repos/{repository}"
    ref = api.request("GET", base + f"/git/ref/tags/{TAG}", missing_ok=True)
    if ref:
        target = ref["object"]
        while target["type"] == "tag":
            target = api.request("GET", base + "/git/tags/" + target["sha"])["object"]
        if target["type"] != "commit":
            raise ReleaseError("Rolling tag does not point to a commit")
        comparison = api.request("GET", base + f"/compare/{target['sha']}...{sha}")
        status = comparison["status"]
        if status == "behind":
            print("Skipping an older build: rolling already points to a newer commit.")
            return False
        if status == "diverged":
            # A force-pushed branch may no longer contain the published commit.
            # Only its current head may replace a release from another lineage.
            head = api.request("GET", base + "/branches/master")["commit"]["sha"]
            if head != sha:
                print("Skipping a superseded build from another branch lineage.")
                return False
        elif status not in ("ahead", "identical"):
            raise ReleaseError("Unexpected commit comparison status")

    release = rolling_release(api, base)
    if release is None:
        # The first release stays hidden until its binary has been uploaded.
        release = api.request("POST", base + "/releases", payload={
            "tag_name": TAG, "target_commitish": sha,
            "name": "Rolling release", "draft": True, "prerelease": False,
        })
    if release.get("immutable"):
        raise ReleaseError("Repository release immutability prevents a rolling release")
    release_id = release["id"]
    old_assets = release["assets"]
    for asset in old_assets:
        if asset["name"] == ASSET:
            api.request("DELETE", base + f"/releases/assets/{asset['id']}")
    api.request("POST", base + f"/releases/{release_id}/assets?name={ASSET}", binary=binary)
    for asset in old_assets:
        if asset["name"] != ASSET:
            api.request("DELETE", base + f"/releases/assets/{asset['id']}")

    if ref:
        api.request("PATCH", base + f"/git/refs/tags/{TAG}", payload={"sha": sha, "force": True})
    else:
        api.request("POST", base + "/git/refs", payload={"ref": f"refs/tags/{TAG}", "sha": sha})
    api.request("PATCH", base + f"/releases/{release_id}", payload={
        "tag_name": TAG, "target_commitish": sha, "name": "Rolling release",
        "draft": False, "prerelease": False, "make_latest": "true",
        "body": (
            "Автоматическая rolling-сборка после успешных проверок push в `master`.\n\n"
            f"Коммит: [{sha}](https://github.com/{repository}/commit/{sha})\n\n"
            f"[Workflow](https://github.com/{repository}/actions/runs/{run_id})\n\n"
            "Скачать и запустить `WarpPocket.exe`. Архивы, checksum-файлы и smoke-отчёты "
            "не публикуются в релизе.\n\n"
            "Приёмка на чистой Windows 10 пока не подтверждена; CI проверяет Windows Server 2022."
        ),
    })
    print(f"Published https://github.com/{repository}/releases/download/{TAG}/{ASSET}")
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if os.environ.get("GITHUB_EVENT_NAME") != "push" or os.environ.get("GITHUB_REF") != "refs/heads/master":
            raise ReleaseError("Publication is allowed only for a push to master")
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise ReleaseError("GITHUB_TOKEN is required")
        publish(GitHub(token), args.exe, repository=os.environ["GITHUB_REPOSITORY"],
                sha=os.environ["GITHUB_SHA"], run_id=os.environ["GITHUB_RUN_ID"])
    except ReleaseError as error:
        print(f"Rolling publication failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError):
        print("Rolling publication failed: invalid executable, API response or workflow context", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
