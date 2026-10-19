"""Offline release tests: never publish or use a real GitHub token."""
from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("warppocket_publish", ROOT / "scripts/publish_rolling.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)
BASE = "/repos/owner/repo"
SHA = "a" * 40
OLD = "b" * 40


class FakeGitHub:
    def __init__(self, *, existing=False, status="ahead", head=SHA):
        self.existing, self.status, self.head = existing, status, head
        self.calls = []
        self.ref = {"object": {"type": "commit", "sha": OLD}} if existing else None
        self.release = {"id": 7, "tag_name": "rolling", "draft": False, "assets": [
            {"id": 1, "name": "WarpPocket.exe"},
            {"id": 2, "name": "WarpPocket.exe.sha256"},
            {"id": 3, "name": "WarpPocket.zip"},
            {"id": 4, "name": "summary.json"},
        ]}

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if method == "GET":
            if "/git/ref/" in path:
                return copy.deepcopy(self.ref)
            if "/git/tags/" in path:
                return {"object": {"type": "commit", "sha": OLD}}
            if "/compare/" in path:
                return {"status": self.status}
            if path.endswith("/branches/master"):
                return {"commit": {"sha": self.head}}
            if "/releases?" in path:
                return [copy.deepcopy(self.release)] if self.existing else []
        if method == "POST" and path.endswith("/releases"):
            return {"id": 7, "assets": []}
        if method in ("POST", "PATCH", "DELETE"):
            return {}
        raise AssertionError((method, path, kwargs))


class PublisherTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="warppocket-publish-tests-")
        self.addCleanup(directory.cleanup)
        self.executable = Path(directory.name) / "WarpPocket.exe"
        self.executable.write_bytes(b"MZ tested executable")
        self.print_patch = mock.patch("builtins.print")
        self.print_patch.start()
        self.addCleanup(self.print_patch.stop)

    def publish(self, api):
        return publisher.publish(api, self.executable, repository="owner/repo", sha=SHA, run_id="123")

    def test_first_publication_stages_draft_uploads_only_exe_and_publishes(self):
        api = FakeGitHub()
        self.assertTrue(self.publish(api))
        creation = next(c for c in api.calls if c[:2] == ("POST", BASE + "/releases"))
        self.assertTrue(creation[2]["payload"]["draft"])
        uploads = [c for c in api.calls if "binary" in c[2]]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0][1], BASE + "/releases/7/assets?name=WarpPocket.exe")
        self.assertEqual(uploads[0][2]["binary"], self.executable.read_bytes())
        self.assertEqual(api.calls[-2][2]["payload"], {"ref": "refs/tags/rolling", "sha": SHA})
        final = api.calls[-1][2]["payload"]
        self.assertFalse(final["draft"])
        self.assertFalse(final["prerelease"])
        self.assertEqual(final["make_latest"], "true")
        self.assertEqual(final["target_commitish"], SHA)
        self.assertIn("/actions/runs/123", final["body"])

    def test_update_replaces_exe_removes_legacy_assets_and_moves_tag(self):
        api = FakeGitHub(existing=True)
        self.assertTrue(self.publish(api))
        deleted = {c[1] for c in api.calls if c[0] == "DELETE"}
        self.assertEqual(deleted, {BASE + f"/releases/assets/{n}" for n in (1, 2, 3, 4)})
        self.assertFalse(any(c[:2] == ("POST", BASE + "/releases") for c in api.calls))
        self.assertEqual(api.calls[-2][:2], ("PATCH", BASE + "/git/refs/tags/rolling"))
        self.assertEqual(api.calls[-2][2]["payload"], {"sha": SHA, "force": True})
        self.assertEqual(len([c for c in api.calls if "binary" in c[2]]), 1)

    def test_late_old_build_cannot_overwrite_newer_release(self):
        api = FakeGitHub(existing=True, status="behind")
        self.assertFalse(self.publish(api))
        self.assertTrue(all(c[0] == "GET" for c in api.calls))

    def test_same_commit_rerun_can_replace_asset(self):
        self.assertTrue(self.publish(FakeGitHub(existing=True, status="identical")))

    def test_only_current_master_can_replace_diverged_lineage(self):
        self.assertTrue(self.publish(FakeGitHub(existing=True, status="diverged")))
        stale = FakeGitHub(existing=True, status="diverged", head="c" * 40)
        self.assertFalse(self.publish(stale))
        self.assertTrue(all(c[0] == "GET" for c in stale.calls))

    def test_annotated_existing_tag_is_resolved(self):
        api = FakeGitHub(existing=True)
        api.ref["object"]["type"] = "tag"
        self.assertTrue(self.publish(api))
        self.assertIn(("GET", BASE + "/git/tags/" + OLD, {}), api.calls)

    def test_failed_first_publication_resumes_existing_draft(self):
        api = FakeGitHub(existing=True)
        api.ref = None
        api.release["draft"] = True
        self.assertTrue(self.publish(api))
        self.assertFalse(any(c[:2] == ("POST", BASE + "/releases") for c in api.calls))

    def test_archive_or_invalid_exe_rejected_before_any_api_call(self):
        for name, content in (("WarpPocket.zip", b"MZ not an exe"), ("WarpPocket.exe", b"PK archive")):
            with self.subTest(name=name):
                path = self.executable.with_name(name)
                path.write_bytes(content)
                api = FakeGitHub()
                with self.assertRaises(publisher.ReleaseError):
                    publisher.publish(api, path, repository="owner/repo", sha=SHA, run_id="123")
                self.assertEqual(api.calls, [])

    def test_immutable_release_fails_before_modifying_it(self):
        api = FakeGitHub(existing=True)
        api.release["immutable"] = True
        with self.assertRaises(publisher.ReleaseError):
            self.publish(api)
        self.assertTrue(all(c[0] == "GET" for c in api.calls))

    def test_failed_upload_does_not_move_tag_or_publish_draft(self):
        api = FakeGitHub()
        original = api.request

        def fail_upload(method, path, **kwargs):
            if "binary" in kwargs:
                raise publisher.ReleaseError("Upload failed")
            return original(method, path, **kwargs)

        with mock.patch.object(api, "request", side_effect=fail_upload):
            with self.assertRaises(publisher.ReleaseError):
                self.publish(api)
        self.assertFalse(any("/git/refs" in c[1] or c[0] == "PATCH" for c in api.calls))

    def test_release_lookup_includes_drafts_and_pagination(self):
        api = mock.Mock()
        api.request.side_effect = [
            [{"tag_name": f"v{i}"} for i in range(100)],
            [{"tag_name": "rolling", "draft": True, "id": 7}],
        ]
        self.assertEqual(publisher.rolling_release(api, BASE)["id"], 7)
        self.assertTrue(api.request.call_args.args[1].endswith("page=2"))

    def test_cli_refuses_pr_branch_push_and_manual_run_before_reading_token(self):
        for event, ref in (("pull_request", "refs/heads/master"), ("push", "refs/heads/topic"),
                           ("workflow_dispatch", "refs/heads/master")):
            with self.subTest(event=event, ref=ref):
                with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": event, "GITHUB_REF": ref}, clear=True):
                    with mock.patch.object(publisher, "GitHub") as client:
                        self.assertEqual(publisher.main(["--exe", str(self.executable)]), 1)
                        client.assert_not_called()


class GitHubClientTests(unittest.TestCase):
    def test_upload_uses_binary_bytes_and_github_upload_host(self):
        client = publisher.GitHub("dummy-token")
        client.opener = mock.Mock()
        client.opener.open.return_value = io.BytesIO(b'{"id": 1}')
        self.assertEqual(client.request("POST", "/repos/owner/repo/releases/7/assets?name=WarpPocket.exe",
                                        binary=b"MZ exe"), {"id": 1})
        request = client.opener.open.call_args.args[0]
        self.assertTrue(request.full_url.startswith("https://uploads.github.com/"))
        self.assertEqual(request.data, b"MZ exe")

    def test_only_optional_404_is_treated_as_missing(self):
        for code, optional in ((404, True), (404, False), (403, True), (500, True)):
            with self.subTest(code=code, optional=optional):
                client = publisher.GitHub("dummy-token")
                client.opener = mock.Mock()
                client.opener.open.side_effect = HTTPError("https://api.github.com", code, "error", {}, None)
                if code == 404 and optional:
                    self.assertIsNone(client.request("GET", "/path", missing_ok=True))
                else:
                    with self.assertRaises(publisher.ReleaseError):
                        client.request("GET", "/path", missing_ok=optional)

    def test_connection_error_does_not_echo_token(self):
        client = publisher.GitHub("dummy-token")
        client.opener = mock.Mock()
        client.opener.open.side_effect = URLError("dummy-token")
        with self.assertRaises(publisher.ReleaseError) as caught:
            client.request("GET", "/path")
        self.assertNotIn("dummy-token", str(caught.exception))

    def test_authenticated_api_calls_do_not_follow_redirects(self):
        self.assertIsNone(publisher.NoRedirect().redirect_request(None, None, 302, "redirect", {},
                                                                 "https://other.example"))


if __name__ == "__main__":
    unittest.main()
