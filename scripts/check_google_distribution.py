# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Read public Google distribution metadata; never authenticate to or invoke MCP."""

import argparse
import hashlib
import http.client
import json
import os
import re
import time
import tomllib
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = "https://raw.githubusercontent.com/VirusTotal/virustotal-mcp/main/"
RESOURCE = "https://ai.virustotal.com/mcp"
FEED = "https://geminicli.com/extensions.json"
METADATA = "https://ai.virustotal.com/.well-known/oauth-authorization-server"
PULL_REQUESTS = {
    "adk_pull_request": "https://api.github.com/repos/google/adk-docs/pulls/2315",
    "google_mcp_pull_request": "https://api.github.com/repos/google/mcp/pulls/67",
}
ISSUES = {
    "adk_recipe_proposal": "https://api.github.com/repos/google/adk-recipes/issues/2755",
    "gemini_cookbook_proposal": "https://api.github.com/repos/google-gemini/cookbook/issues/1404",
}
GITHUB_URLS = {*PULL_REQUESTS.values(), *ISSUES.values()}
PUBLIC_FILES = {
    "gemini_manifest": "gemini-extension.json",
    "antigravity_manifest": "plugins/antigravity/plugin.json",
    "antigravity_mcp": "plugins/antigravity/mcp_config.json",
    "google_guide": "docs/google-clients.md",
    "antigravity_guide": "plugins/antigravity/README.md",
}
ALLOWED_URLS = {FEED, METADATA, *GITHUB_URLS, *(RAW + p for p in PUBLIC_FILES.values())}
MAX_BYTES = 4 * 1024 * 1024
MAX_FEED_ENTRIES = 10_000
SOCKET_TIMEOUT = 10
READ_SECONDS = 20


def now():
    return datetime.now(UTC).isoformat()


class CheckFailure(Exception):
    def __init__(self, status, reason, http_status=None):
        self.status = status
        self.reason = reason
        self.http_status = http_status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CheckFailure("error", "redirect_not_allowed", code)


def fetch(url, *, token=None):
    """Exact endpoint allowlist, no redirects/proxies, bounded body and socket waits."""
    if url not in ALLOWED_URLS:
        raise CheckFailure("error", "url_not_allowed")
    headers = {"Accept": "application/json", "User-Agent": "virustotal-distribution-monitor/1"}
    if url in GITHUB_URLS:
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2026-03-10"
        if token:
            headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + READ_SECONDS
    try:
        with opener.open(request, timeout=SOCKET_TIMEOUT) as response:
            if response.status != 200:
                raise CheckFailure("error", "unexpected_http_status", response.status)
            body = bytearray()
            while True:
                if time.monotonic() > deadline:
                    raise CheckFailure("transient", "read_deadline")
                chunk = response.read1(min(64 * 1024, MAX_BYTES + 1 - len(body)))
                body.extend(chunk)
                if len(body) > MAX_BYTES:
                    raise CheckFailure("error", "response_too_large")
                if not chunk:
                    break
            return bytes(body), {
                "http_status": 200,
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
    except urllib.error.HTTPError as exc:
        transient = (
            exc.code in {408, 429}
            or exc.code >= 500
            or (
                exc.code == 403
                and (
                    exc.headers.get("X-RateLimit-Remaining") == "0"
                    or exc.headers.get("Retry-After")
                )
            )
        )
        code = exc.code
        exc.close()
        raise CheckFailure("transient" if transient else "error", "http_error", code) from None
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        # Never include exception text, response payloads, headers or credentials.
        raise CheckFailure("transient", "network_error") from None


def object_json(body):
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("expected_object")
    return value


def check_manifest(name, body, version):
    data = object_json(body)
    if name == "gemini_manifest":
        server = data["mcpServers"]["virustotal"]
        valid = (
            data["name"] == "virustotal"
            and data["version"] == version
            and server["httpUrl"] == RESOURCE
            and server["oauth"]["enabled"] is True
            and server["oauth"]["scopes"]
            == ["vt:reports:read", "vt:submissions:write", "vt:network-analysis:write"]
        )
    elif name == "antigravity_manifest":
        prompts = data.get("suggestedPrompts")
        valid = (
            set(data)
            == {"name", "displayName", "version", "description", "logo", "suggestedPrompts"}
            and data["name"] == "virustotal"
            and data["displayName"] == "VirusTotal"
            and isinstance(data["version"], str)
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", data["version"]) is not None
            and isinstance(data["description"], str)
            and bool(data["description"].strip())
            and data["logo"] == "assets/virustotal-icon-512.png"
            and isinstance(prompts, list)
            and len(prompts) == 3
            and all(isinstance(prompt, str) and prompt.strip() for prompt in prompts)
        )
    else:
        valid = data == {"mcpServers": {"virustotal": {"serverUrl": RESOURCE}}}
    if not valid:
        raise CheckFailure("error", "manifest_mismatch")
    return "available", {"reason": "public_metadata_matches"}


def check_feed(body, version):
    data = json.loads(body)
    if not isinstance(data, list) or not 1 <= len(data) <= MAX_FEED_ENTRIES:
        raise ValueError("invalid_feed")
    matches = []
    for entry in data:
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            raise ValueError("invalid_feed_entry")
        if entry["url"].rstrip("/") == "https://github.com/VirusTotal/virustotal-mcp":
            matches.append(entry)
    details = {"entries": len(data), "expected_version": version}
    if not matches:
        return "pending", {**details, "reason": "canonical_repository_not_listed"}
    if len(matches) != 1:
        raise ValueError("duplicate_canonical_entry")
    entry = matches[0]
    if entry.get("extensionName") != "virustotal" or not isinstance(
        entry.get("extensionVersion"), str
    ):
        raise ValueError("invalid_canonical_entry")
    observed = entry["extensionVersion"]
    if len(observed) > 64:
        raise ValueError("invalid_version")
    details["observed_version"] = observed
    if observed != version:
        return "stale-feed", {**details, "reason": "gallery_version_differs"}
    return "listed", {**details, "reason": "canonical_repository_and_version_found"}


def check_pull_request(body, url):
    data = object_json(body)
    if data["url"] != url or data["state"] not in {"open", "closed"}:
        raise ValueError("unexpected_pull_request")
    if not isinstance(data["merged"], bool):
        raise ValueError("invalid_merged_status")
    if data["merged"]:
        return "merged", {"reason": "pr_merged_not_catalog_publication"}
    if data["state"] == "open":
        return "pending", {"reason": "maintainer_review"}
    return "error", {"reason": "pull_request_closed_without_merge"}


def check_issue(body, url):
    data = object_json(body)
    if data["url"] != url or data["state"] not in {"open", "closed"} or "pull_request" in data:
        raise ValueError("unexpected_issue")
    if data["state"] == "open":
        return "pending", {"reason": "proposal_open_not_acceptance"}
    return "closed", {"reason": "proposal_closed_not_acceptance"}


def inspect(name, url, body, version):
    if name in {"gemini_manifest", "antigravity_manifest", "antigravity_mcp"}:
        return check_manifest(name, body, version)
    if name == "gemini_gallery":
        return check_feed(body, version)
    if name in PULL_REQUESTS:
        return check_pull_request(body, url)
    if name in ISSUES:
        return check_issue(body, url)
    if name == "oauth_metadata":
        data = object_json(body)
        if data["issuer"] != "https://ai.virustotal.com" or data["registration_endpoint"] != (
            "https://ai.virustotal.com/oauth/register"
        ):
            raise ValueError("oauth_metadata_mismatch")
        return "available", {"reason": "public_oauth_metadata_only_no_login_or_mcp_call"}
    if "VirusTotal" not in body.decode("utf-8"):
        raise ValueError("unexpected_document")
    return "available", {"reason": "public_document_only_not_marketplace_approval"}


def collect(version, *, token=None, reader=fetch):
    started = now()
    targets = {name: RAW + path for name, path in PUBLIC_FILES.items()}
    targets.update(oauth_metadata=METADATA, gemini_gallery=FEED, **PULL_REQUESTS, **ISSUES)
    results = []
    for name, url in targets.items():
        result = {"name": name, "url": url, "checked_at": now()}
        try:
            body, transport = reader(url, token=token)
            result.update(transport)
            status, details = inspect(name, url, body, version)
            result.update(status=status, **details)
        except CheckFailure as exc:
            result.update(status=exc.status, reason=exc.reason)
            if exc.http_status is not None:
                result["http_status"] = exc.http_status
        except (ValueError, KeyError, TypeError, RecursionError):
            result.update(status="error", reason="invalid_public_metadata")
        results.append(result)
    results.append(
        {
            "name": "antigravity_marketplace",
            "checked_at": now(),
            "status": "pending",
            "reason": "review_status_not_publicly_verified_no_marketplace_api_check",
        }
    )
    errors = sum(item["status"] == "error" for item in results)
    incomplete = any(item["status"] == "transient" for item in results)
    return {
        "schema_version": 1,
        "started_at": started,
        "finished_at": now(),
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "expected_version": version,
        "read_only": True,
        "outcome": "error" if errors else "incomplete" if incomplete else "observed",
        "checks": results,
        "errors": errors,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    report = collect(version, token=os.environ.get("GITHUB_TOKEN"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        "## Google distribution",
        "",
        f"Checked: {report['finished_at']}",
        f"Outcome: {report['outcome']}",
        "",
        "| Check | Status | Detail |",
        "| --- | --- | --- |",
    ]
    lines += [
        f"| {item['name']} | {item['status']} | {item['reason']} |" for item in report["checks"]
    ]
    lines += [
        "",
        "Public metadata only. Pending reviews, stale feeds and transient network errors are "
        "not approval or proof of a working authenticated client session.",
        "",
    ]
    summary = "\n".join(lines)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write(summary)
    print(summary)
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
