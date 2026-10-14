# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline checks for distribution parsing, network bounds and credential isolation."""

import importlib.util
import io
import json
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "google_distribution", ROOT / "scripts/check_google_distribution.py"
)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


class Response(io.BytesIO):
    status = 200


class DistributionTests(unittest.TestCase):
    def test_only_exact_public_urls_are_fetched_and_only_github_api_gets_token(self):
        calls = []

        def open_request(request, timeout):
            calls.append(request)
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(timeout, 10)
            return Response(b"{}")

        with patch.object(monitor.urllib.request.OpenerDirector, "open", side_effect=open_request):
            for url in monitor.ALLOWED_URLS:
                monitor.fetch(url, token="synthetic-secret")
            for url in (
                "http://geminicli.com/extensions.json",
                "https://api.github.com.evil.test/repos/google/mcp/pulls/67",
                "https://user@api.github.com/repos/google/mcp/pulls/67",
                monitor.FEED + "?token=secret",
                "https://ai.virustotal.com/mcp",
                "http://127.0.0.1/",
            ):
                with self.assertRaises(monitor.CheckFailure):
                    monitor.fetch(url, token="synthetic-secret")
        self.assertEqual(len(calls), len(monitor.ALLOWED_URLS))
        for request in calls:
            self.assertEqual(
                request.get_header("Authorization"),
                "Bearer synthetic-secret" if request.full_url in monitor.GITHUB_URLS else None,
            )

    def test_redirects_never_create_a_followup_request(self):
        for destination in (monitor.FEED, "https://evil.test/", "http://127.0.0.1/"):
            with self.assertRaises(monitor.CheckFailure) as failure:
                monitor.NoRedirect().redirect_request(None, None, 302, "", {}, destination)
            self.assertEqual(failure.exception.reason, "redirect_not_allowed")

    def test_body_and_read_time_bounds(self):
        with (
            patch.object(monitor, "MAX_BYTES", 4),
            patch.object(
                monitor.urllib.request.OpenerDirector, "open", return_value=Response(b"12345")
            ),
        ):
            with self.assertRaises(monitor.CheckFailure) as failure:
                monitor.fetch(monitor.FEED)
            self.assertEqual(failure.exception.reason, "response_too_large")
        with (
            patch.object(monitor.time, "monotonic", side_effect=[0, 21]),
            patch.object(
                monitor.urllib.request.OpenerDirector, "open", return_value=Response(b"[]")
            ),
        ):
            with self.assertRaises(monitor.CheckFailure) as failure:
                monitor.fetch(monitor.FEED)
            self.assertEqual(failure.exception.status, "transient")
        with patch.object(
            monitor.urllib.request.OpenerDirector,
            "open",
            side_effect=monitor.http.client.IncompleteRead(b"synthetic-secret"),
        ):
            with self.assertRaises(monitor.CheckFailure) as failure:
                monitor.fetch(monitor.FEED)
            self.assertEqual(failure.exception.reason, "network_error")

    def test_http_failures_are_sanitized_and_rate_limits_are_transient(self):
        for code, headers, expected in (
            (429, {}, "transient"),
            (503, {}, "transient"),
            (403, {"X-RateLimit-Remaining": "0"}, "transient"),
            (403, {}, "error"),
            (404, {}, "error"),
        ):
            failure = urllib.error.HTTPError(
                monitor.FEED, code, "synthetic-secret", headers, io.BytesIO(b"synthetic-secret")
            )
            with patch.object(monitor.urllib.request.OpenerDirector, "open", side_effect=failure):
                with self.assertRaises(monitor.CheckFailure) as caught:
                    monitor.fetch(monitor.FEED)
            self.assertEqual(caught.exception.status, expected)
            self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_feed_checks_canonical_identity_and_distinguishes_staleness(self):
        entry = {
            "url": "https://github.com/VirusTotal/virustotal-mcp",
            "extensionName": "virustotal",
            "extensionVersion": "0.9.2",
        }
        status, details = monitor.check_feed(json.dumps([entry]), "0.9.8")
        self.assertEqual(status, "stale-feed")
        self.assertEqual(details["observed_version"], "0.9.2")
        self.assertEqual(monitor.check_feed(json.dumps([entry]), "0.9.2")[0], "listed")
        entry["url"] += "-imposter"
        self.assertEqual(monitor.check_feed(json.dumps([entry]), "0.9.2")[0], "pending")
        for invalid in ([], {}, [None], [{"url": 7}], [entry] * 10001):
            with self.assertRaises(ValueError):
                monitor.check_feed(json.dumps(invalid), "0.9.8")
        entry["url"] = "https://github.com/VirusTotal/virustotal-mcp"
        with self.assertRaises(ValueError):
            monitor.check_feed(json.dumps([entry, entry]), "0.9.8")

    def test_pr_merge_and_open_review_are_not_catalog_publication(self):
        url = monitor.PULL_REQUESTS["adk_pull_request"]
        for state, merged, expected in (
            ("open", False, "pending"),
            ("closed", True, "merged"),
            ("closed", False, "error"),
        ):
            result = monitor.check_pull_request(
                json.dumps({"url": url, "state": state, "merged": merged}), url
            )
            self.assertEqual(result[0], expected)
        with self.assertRaises(ValueError):
            monitor.check_pull_request(
                json.dumps({"url": url, "state": "open", "merged": "false"}), url
            )

    def test_antigravity_presentation_stays_within_the_published_package(self):
        manifest = json.loads((ROOT / "plugins/antigravity/plugin.json").read_text())
        self.assertEqual(
            monitor.check_manifest("antigravity_manifest", json.dumps(manifest), "0.9.9")[0],
            "available",
        )
        for changed in (
            {"name": "another-plugin"},
            {"displayName": "Another publisher"},
            {"version": None},
            {"version": "preview"},
            {"description": " "},
            {"logo": "https://example.com/logo.png"},
            {"logo": "../assets/virustotal-icon-512.png"},
            {"suggestedPrompts": ["One prompt"]},
            {"suggestedPrompts": ["One", "Two", " "]},
            {"suggestedPrompts": ["One", "Two", 3]},
            {"author": {"email": "unverified@example.com"}},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(monitor.CheckFailure):
                    monitor.check_manifest(
                        "antigravity_manifest", json.dumps(manifest | changed), "0.9.9"
                    )

    def test_issue_state_is_informational_and_not_a_pull_request_approval(self):
        url = monitor.ISSUES["adk_recipe_proposal"]
        for state, expected in (("open", "pending"), ("closed", "closed")):
            status, details = monitor.check_issue(json.dumps({"url": url, "state": state}), url)
            self.assertEqual(status, expected)
            self.assertIn("not_acceptance", details["reason"])
        for invalid in (
            {"url": url, "state": "accepted"},
            {"url": url + "1", "state": "open"},
            {"url": url, "state": "closed", "pull_request": {}},
        ):
            with self.assertRaises(ValueError):
                monitor.check_issue(json.dumps(invalid), url)

    def test_one_failure_does_not_hide_other_targets_or_echo_response_data(self):
        visited = []

        def read(url, token):
            visited.append(url)
            if url == monitor.FEED:
                raise monitor.CheckFailure("transient", "http_error", 429)
            if url in monitor.GITHUB_URLS:
                return json.dumps({"url": url, "state": "open", "merged": False}), {}
            # Includes an error payload that must never reach the report.
            return b'{"unexpected":"synthetic-secret"}', {}

        report = monitor.collect("0.9.8", reader=read, token="synthetic-secret")
        self.assertEqual(set(visited), monitor.ALLOWED_URLS)
        states = {row["name"]: row["status"] for row in report["checks"]}
        self.assertEqual(states["gemini_gallery"], "transient")
        self.assertEqual(states["adk_pull_request"], "pending")
        self.assertGreater(report["errors"], 0)
        self.assertNotIn("synthetic-secret", json.dumps(report))

    def test_valid_public_metadata_with_pending_review_and_stale_feed_is_not_failure(self):
        def read(url, token):
            if url == monitor.FEED:
                data = [
                    {
                        "url": "https://github.com/VirusTotal/virustotal-mcp",
                        "extensionName": "virustotal",
                        "extensionVersion": "0.9.2",
                    }
                ]
            elif url in monitor.GITHUB_URLS:
                data = {"url": url, "state": "open", "merged": False}
            elif url == monitor.METADATA:
                data = {
                    "issuer": "https://ai.virustotal.com",
                    "registration_endpoint": "https://ai.virustotal.com/oauth/register",
                }
            else:
                body = (ROOT / url.removeprefix(monitor.RAW)).read_bytes()
                if not url.endswith(".json"):
                    return body, {}
                data = json.loads(body)
                if url.endswith("gemini-extension.json"):
                    data["version"] = "0.9.8"
            return json.dumps(data), {}

        report = monitor.collect("0.9.8", reader=read)
        self.assertEqual(report["errors"], 0)
        self.assertEqual(report["outcome"], "observed")
        self.assertIn("stale-feed", [row["status"] for row in report["checks"]])


if __name__ == "__main__":
    unittest.main()
