# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Bounded Registry operations with release-verified PyPI distribution."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

REGISTRY = "https://registry.modelcontextprotocol.io"
OFFICIAL = "io.modelcontextprotocol.registry/official"
# Canonical JSON hashes pin the entire remote and package configuration.
# The package release is independent of the Registry metadata version.
IDENTITIES = {
    "VirusTotal/virustotal-mcp": {
        "id": 1361592455,
        "oidc_subject": "repo:VirusTotal@7701252/virustotal-mcp@1361592455:ref:refs/heads/main",
        "name": "io.github.VirusTotal/virustotal-mcp",
        "version": "0.9.9",
        "manifest_sha256": "b8591121218c20a5da9e89840deeb4411ed4705ea3445066539dcb558a7dc87a",
        "package_release": {
            "version": "0.9.9",
            "source_sha": "a450cff05c1377979e3251616dbded02a44e184e",
            "tag_object_sha": "8df433ed7dcfaf6cdb3ad72cc8942e8e5703bbbb",
            "manifest_sha256": "81e0456540be9e6c784a5d9700a73cdadff1f77c55d23c9e4d00f81772e1b5bd",
        },
    },
    "king-tero/vt-mcp": {
        "id": 1359828317,
        "oidc_subject": "repo:king-tero@4201239/vt-mcp@1359828317:ref:refs/heads/main",
        "name": "io.github.king-tero/vt-mcp",
        "version": "0.8.0",
        "manifest_sha256": "86c09dc2d84b540291e56813f13e6747cc6ae0f138adb9e4d5575d769f0a155d",
    },
}
PREVIOUS = {
    "VirusTotal/virustotal-mcp": (
        {
            "version": "0.8.2",
            "manifest_sha256": "294e3daa8f45e8f6b6050ab7cce140489272844c911afe6e3aca60843b0aa0e8",
        },
        {
            "version": "0.8.3",
            "manifest_sha256": "fdcfa9f92f6945e38bfecc65d5f22c5ce2caf908573bc39a059a79fd3daae40b",
        },
        {
            "version": "0.8.4",
            "manifest_sha256": "5295fde5e5c1dcab1061763236c332d8ef1ec4ec7b108d17da638cad0873f04d",
        },
        {
            "version": "0.8.5",
            "manifest_sha256": "a17f254fc684ca7ce8cd46f5244f2667f91a858b116528cc1fc55a6677a6779a",
        },
        {
            "version": "0.8.6",
            "manifest_sha256": "6a5600b9d522ea989228caae71ad3f3250431f76516297dbd41b7cc2f462782e",
        },
        {
            "version": "0.8.7",
            "manifest_sha256": "c85f2391f0306c21bb5e55f11c78c4aa33b599f0278ac430af42c184d1821b99",
        },
        {
            "version": "0.9.0",
            "manifest_sha256": "c5a0553072f11e1c5f51d8d1b57353825c79333ccc72c0bc8b76a3775a75864b",
        },
        {
            "version": "0.9.1",
            "manifest_sha256": "972d39aaa03bb52172c1f4e3b615ab0d28985282ef3da69d369c3033f95e6adf",
        },
        {
            "version": "0.9.2",
            "manifest_sha256": "16f520a86c93931a85f8cd677428263f2d48ee30787ad1cb6120491c86950b0e",
        },
        {
            "version": "0.9.3",
            "manifest_sha256": "cd05d73567bb82d89ed000b2596c2a89b778896685b53335c0a4c95357e8c03b",
        },
        {
            "version": "0.9.5",
            "manifest_sha256": "c6e6563b26842b894d50d5b25c050e945756c27cf7bee7a1212ff9c2b8152016",
        },
        {
            "version": "0.9.6",
            "manifest_sha256": "0fe5606abbcb36344295240d90377ad1388bb600f90e75c5a04e1fff271008cd",
        },
        {
            "version": "0.9.8",
            "manifest_sha256": "10fc873ed9bb56667c58f3e29becf2dff213a320fe44aaaec859ecf89a844909",
        },
    )
}
LEGACY_VERSIONS = {"0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7"}
LEGACY_OPERATIONS = {"deprecate-legacy", "restore-legacy"}
LEGACY_MESSAGE = "Superseded by io.github.VirusTotal/virustotal-mcp 0.9.5. Use the current entry."
OPERATIONS = {"verify-identity", "publish", "retire", "restore"} | LEGACY_OPERATIONS
RETIRE_MESSAGES = {
    "king-tero/vt-mcp": "Moved to io.github.VirusTotal/virustotal-mcp.",
    "VirusTotal/virustotal-mcp": "Temporarily retired for Registry identity recovery.",
}
LIMIT = 1024 * 1024


class Rejected(Exception):
    """Only fixed diagnostic codes may reach logs or the result artifact."""


def require(condition, code):
    if not condition:
        raise Rejected(code)


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def identity(environ):
    repository = environ.get("GITHUB_REPOSITORY")
    require(repository in IDENTITIES, "repository_not_allowed")
    selected = IDENTITIES[repository]
    require(environ.get("GITHUB_REPOSITORY_ID") == str(selected["id"]), "repository_id_mismatch")
    return repository, selected


def manifest_contract(manifest, selected):
    require(digest(manifest) == selected["manifest_sha256"], "manifest_contract_mismatch")


def context(environ):
    repository, selected = identity(environ)
    sha = environ.get("GITHUB_SHA", "")
    operation = environ.get("REGISTRY_OPERATION", "verify-identity")
    require(operation in OPERATIONS, "invalid_operation")
    target = environ.get("REGISTRY_TARGET_VERSION", "")
    if operation in LEGACY_OPERATIONS:
        require(
            repository == "VirusTotal/virustotal-mcp" and target in LEGACY_VERSIONS,
            "invalid_legacy_target",
        )
    else:
        require(not target, "unexpected_target_version")
    require(
        re.fullmatch(r"[a-f0-9]{40}", sha)
        and environ.get("REVIEWED_SHA") == sha
        and environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and environ.get("GITHUB_REF") == "refs/heads/main"
        and environ.get("GITHUB_WORKFLOW_REF")
        == f"{repository}/.github/workflows/mcp-registry.yml@refs/heads/main",
        "reviewed_main_required",
    )
    return {
        "repository": repository,
        "sha": sha,
        "operation": operation,
        "target_version": target,
        **selected,
    }


def child_env(environ, *, oidc=False):
    keys = ["PATH", "HOME", "SSL_CERT_FILE", "SSL_CERT_DIR"]
    keys += (
        ["ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"] if oidc else ["GH_TOKEN"]
    )
    # No inherited debug, shell tracing, pagers, alternate GH host or proxy options.
    return {
        **{k: environ[k] for k in keys if k in environ},
        "GH_PROMPT_DISABLED": "1",
        "GH_PAGER": "cat",
        "NO_COLOR": "1",
    }


def command(args, environ, *, timeout=90):
    try:
        result = subprocess.run(
            args,
            env=environ,
            capture_output=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Rejected("command_unavailable_or_timed_out") from None
    require(result.returncode == 0, "command_failed")
    return result.stdout


def github(path, environ, *, binary=False):
    args = ["gh", "api", "--hostname", "github.com", "--method", "GET", path]
    if binary:
        args += ["-H", "Accept: application/octet-stream"]
    raw = command(
        args,
        child_env(environ),
        timeout=30,
    )
    require(len(raw) <= LIMIT, "github_response_too_large")
    return raw if binary else json.loads(raw)


def github_preflight(current, environ):
    prefix = f"repos/{current['repository']}"
    repository = github(prefix, environ)  # No trailing slash on the repository root.
    require(
        type(repository.get("id")) is int
        and repository["id"] == current["id"]
        and repository.get("full_name") == current["repository"]
        and type(repository.get("private")) is bool,
        "github_repository_mismatch",
    )
    # Published source metadata must identify a publicly inspectable repository.
    require(not repository["private"], "private_repository_rejected")
    main = github(prefix + "/git/ref/heads/main", environ)
    require(main.get("object", {}).get("sha") == current["sha"], "main_has_changed")
    runs = github(
        prefix + "/actions/workflows/ci.yml/runs"
        f"?head_sha={current['sha']}&event=push&branch=main&per_page=100",
        environ,
    )["workflow_runs"]
    require(isinstance(runs, list), "invalid_ci_response")
    require(
        any(
            r.get("head_sha") == current["sha"]
            and r.get("head_branch") == "main"
            and r.get("event") == "push"
            and r.get("status") == "completed"
            and r.get("conclusion") == "success"
            and r.get("path") == ".github/workflows/ci.yml"
            and r.get("repository", {}).get("id") == current["id"]
            and r.get("head_repository", {}).get("id") == current["id"]
            for r in runs
        ),
        "successful_main_ci_required",
    )


def pypi_get(version):
    connection = http.client.HTTPSConnection("pypi.org", timeout=30)
    try:
        connection.request(
            "GET",
            f"/pypi/vt-mcp/{version}/json",
            headers={"Accept": "application/json", "Cache-Control": "no-cache"},
        )
        response = connection.getresponse()
        require(response.status == 200, "pypi_version_not_available")
        require(
            response.getheader("Content-Encoding", "identity") == "identity", "compressed_response"
        )
        raw = response.read(LIMIT + 1)
        require(len(raw) <= LIMIT, "pypi_response_too_large")
        return json.loads(raw)
    finally:
        connection.close()


def pypi_preflight(current, environ):
    """Link both public distributions to the reviewed annotated release tag."""
    release_pin = current["package_release"]
    version, prefix = release_pin["version"], f"repos/{current['repository']}"
    value = pypi_get(version)
    info = value["info"]
    require(
        info.get("name") == "vt-mcp" and info.get("version") == version,
        "pypi_identity_mismatch",
    )
    description = info.get("description")
    require(
        isinstance(description, str)
        and re.findall(r"mcp-name:\s*([^\s<>]+)", description) == [current["name"]],
        "pypi_ownership_marker_mismatch",
    )
    files = {
        f"vt_mcp-{version}-py3-none-any.whl": "bdist_wheel",
        f"vt_mcp-{version}.tar.gz": "sdist",
    }
    rows = value["urls"]
    require(
        isinstance(rows, list)
        and len(rows) == 2
        and {f.get("filename") for f in rows} == set(files)
        and all(
            f.get("packagetype") == files[f["filename"]]
            and f.get("yanked") is False
            and re.fullmatch(r"[0-9a-f]{64}", f.get("digests", {}).get("sha256", ""))
            for f in rows
        ),
        "pypi_distributions_mismatch",
    )
    tag_name = "v" + version
    ref = github(prefix + "/git/ref/tags/" + tag_name, environ)
    require(
        ref["object"].get("type") == "tag"
        and ref["object"].get("sha") == release_pin["tag_object_sha"],
        "release_tag_mismatch",
    )
    tag = github(prefix + "/git/tags/" + ref["object"]["sha"], environ)
    require(
        tag.get("tag") == tag_name
        and tag["object"].get("type") == "commit"
        and tag["object"].get("sha") == release_pin["source_sha"],
        "release_source_mismatch",
    )
    pinned = re.findall(r"^SHA256SUMS-SHA256: ([0-9a-f]{64})$", tag["message"], re.MULTILINE)
    require(pinned == [release_pin["manifest_sha256"]], "release_manifest_not_pinned")
    release = github(prefix + "/releases/tags/" + tag_name, environ)
    require(
        release.get("tag_name") == tag_name
        and release.get("draft") is False
        and release.get("prerelease") is False
        and release.get("published_at"),
        "release_not_published",
    )
    assets = release["assets"]
    require(
        isinstance(assets, list)
        and len(assets) == 3
        and {a.get("name") for a in assets} == {*files, "SHA256SUMS"}
        and all(
            type(a.get("id")) is int and a["id"] > 0 and a.get("state") == "uploaded"
            for a in assets
        ),
        "release_assets_mismatch",
    )
    manifest_asset = next(a for a in assets if a["name"] == "SHA256SUMS")
    manifest = github(prefix + f"/releases/assets/{manifest_asset['id']}", environ, binary=True)
    require(hashlib.sha256(manifest).hexdigest() == pinned[0], "release_manifest_mismatch")
    lines = manifest.decode("ascii").splitlines()
    require(len(lines) == 2, "invalid_release_manifest")
    expected = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(
            match is not None and match[2] in files and match[2] not in expected,
            "invalid_release_manifest",
        )
        expected[match[2]] = match[1]
    require(
        all(f["digests"]["sha256"] == expected[f["filename"]] for f in rows)
        and all(
            a.get("digest") == "sha256:" + {**expected, "SHA256SUMS": pinned[0]}[a["name"]]
            for a in assets
        ),
        "pypi_release_hash_mismatch",
    )
    return {
        "name": "vt-mcp",
        "version": version,
        "source_sha": release_pin["source_sha"],
        "tag_object_sha": ref["object"]["sha"],
        "manifest_sha256": pinned[0],
        "files": expected,
    }


def registry_get(path):
    connection = http.client.HTTPSConnection("registry.modelcontextprotocol.io", timeout=30)
    try:
        connection.request(
            "GET", path, headers={"Accept": "application/json", "Cache-Control": "no-cache"}
        )
        response = connection.getresponse()
        if response.status == 404:
            return None
        require(response.status == 200, "registry_read_failed")
        require(
            response.getheader("Content-Encoding", "identity") == "identity", "compressed_response"
        )
        raw = response.read(LIMIT + 1)
        require(len(raw) <= LIMIT, "registry_response_too_large")
        return json.loads(raw)
    finally:
        connection.close()


def public_entry(value, selected):
    if value is None:
        return {"name": selected["name"], "version": selected["version"], "status": "absent"}
    manifest_contract(value["server"], selected)
    official = value["_meta"][OFFICIAL]
    status = official.get("status")
    require(status in {"active", "deprecated", "deleted"}, "invalid_registry_status")
    message = official.get("statusMessage")
    require(
        message is None or (isinstance(message, str) and len(message) <= 500),
        "invalid_status_message",
    )
    require(status != "active" or message is None, "active_status_has_message")
    return {
        "name": selected["name"],
        "version": selected["version"],
        "status": status,
        "manifest_sha256": selected["manifest_sha256"],
        "status_message_sha256": digest(message) if message is not None else None,
    }


def snapshot():
    observed = {}
    for repository, selected in IDENTITIES.items():
        versions = {selected["version"]: selected}
        for previous in PREVIOUS.get(repository, ()):
            versions[previous["version"]] = {**selected, **previous}
        prefix = "/v0.1/servers/" + quote(selected["name"], safe="") + "/versions"
        listing = registry_get(prefix + "?include_deleted=true")
        listed = {}
        if listing is not None:
            rows, metadata = listing["servers"], listing["metadata"]
            # This specific endpoint returns all versions, not a paginated search.
            require(
                isinstance(rows, list) and len(rows) <= len(versions),
                "unexpected_registry_versions",
            )
            require(
                type(metadata.get("count")) is int
                and metadata["count"] == len(rows)
                and not any(metadata.get(k) for k in ("nextCursor", "next_cursor", "cursor")),
                "incomplete_registry_versions",
            )
            for row in rows:
                version = row["server"]["version"]
                require(
                    version in versions and version not in listed, "unexpected_registry_versions"
                )
                listed[version] = public_entry(row, versions[version])
        for version, contract in versions.items():
            exact = public_entry(
                registry_get(prefix + "/" + version + "?include_deleted=true"), contract
            )
            require(
                listed.get(version, public_entry(None, contract)) == exact,
                "registry_views_disagree",
            )
            is_current = version == selected["version"]
            if not is_current:
                legacy = repository == "VirusTotal/virustotal-mcp" and version in LEGACY_VERSIONS
                require(
                    exact["status"] == "active"
                    or (
                        legacy
                        and exact["status"] == "deprecated"
                        and exact["status_message_sha256"] == digest(LEGACY_MESSAGE)
                    ),
                    "previous_version_status_changed",
                )
            observed[repository if is_current else f"{repository}@{version}"] = exact
    return observed


def action(current, before):
    own = before[current["repository"]]["status"]
    operation = current["operation"]
    if operation == "verify-identity":
        return None
    if operation in {"publish", "restore"}:
        require(
            all(
                s["status"] in {"absent", "deleted"}
                for s in before.values()
                if s["name"] != current["name"]
            ),
            "counterpart_reserves_remote_url",
        )
    if current["repository"] == "VirusTotal/virustotal-mcp":
        personal = before["king-tero/vt-mcp"]
        require(
            personal["status"] == "deleted"
            and personal["status_message_sha256"] == digest(RETIRE_MESSAGES["king-tero/vt-mcp"]),
            "personal_retirement_changed",
        )
    if operation in LEGACY_OPERATIONS:
        require(own == "active", "current_entry_must_be_active")
        version = current["target_version"]
        target = before[f"{current['repository']}@{version}"]
        status = "deprecated" if operation == "deprecate-legacy" else "active"
        if target["status"] == status:
            return None
        args = ["status", "--status", status]
        if status == "deprecated":
            args += ["--message", LEGACY_MESSAGE]
        return args + [current["name"], version]
    if operation == "publish":
        require(own in {"absent", "active"}, "existing_version_requires_restore")
        return ["publish", "server.json"] if own == "absent" else None
    require(own != "absent", "own_version_missing")
    if operation == "retire":
        return (
            [
                "status",
                "--status",
                "deleted",
                "--message",
                RETIRE_MESSAGES[current["repository"]],
                current["name"],
                current["version"],
            ]
            if own != "deleted"
            else None
        )
    return (
        ["status", "--status", "active", current["name"], current["version"]]
        if own != "active"
        else None
    )


def credential_paths():
    home = Path.home()
    return [
        home / ".config/mcp-publisher/token.json",
        home / ".mcp_publisher_token",
        home / ".mcpregistry_github_token",
        home / ".mcpregistry_registry_token",
        Path.cwd() / ".mcpregistry_github_token",
        Path.cwd() / ".mcpregistry_registry_token",
    ]


def fresh_credentials():
    paths = credential_paths()
    require(not any(p.exists() or p.is_symlink() for p in paths), "preexisting_credentials")
    for parent in (paths[0].parent, paths[0].parent.parent):
        require(
            not parent.is_symlink() and (not parent.exists() or parent.is_dir()),
            "unsafe_credential_directory",
        )
    return paths[0]


def check_credential(path, current):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            require(
                stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.getuid()
                and info.st_nlink == 1
                and info.st_size <= 16384,
                "credential_rejected",
            )
            saved = json.loads(os.read(descriptor, 16385))
        finally:
            os.close(descriptor)
        require(
            saved["method"] == "github-oidc" and saved["registry"] == REGISTRY,
            "credential_rejected",
        )
        parts = saved["token"].split(".")
        require(
            len(parts) == 3 and all(re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts),
            "credential_rejected",
        )

        def decode(part):
            return json.loads(
                base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
            )

        header, claims = decode(parts[0]), decode(parts[1])
        now = time.time()
        # The trusted HTTPS exchange authenticates this new token; this decoding
        # checks the expected claims, not a separate local signature verification.
        require(
            header["alg"] == "EdDSA"
            and claims["iss"] == "mcp-registry"
            and claims["auth_method"] == "github-oidc",
            "credential_rejected",
        )
        require(
            claims.get("auth_method_sub") == current["oidc_subject"],
            "credential_subject_mismatch",
        )
        require(
            claims.get("permissions")
            == [{"action": "publish", "resource": current["name"].split("/")[0] + "/*"}],
            "credential_permissions_mismatch",
        )
        require(
            all(type(claims.get(k)) is int for k in ("iat", "nbf", "exp"))
            and now - 300 <= claims["iat"] <= now + 60
            and claims["nbf"] <= now + 60 < claims["exp"]
            and claims["iat"] < claims["exp"],
            "credential_time_invalid",
        )
    except (KeyError, ValueError, TypeError, AttributeError, OSError):
        raise Rejected("credential_rejected") from None


@contextmanager
def authenticated(publisher, current, environ, result):
    credential = fresh_credentials()
    env = child_env(environ, oidc=True)
    try:
        command([publisher, "login", "github-oidc"], env)
        check_credential(credential, current)
        result["identity_verified"] = True
        yield
    finally:
        try:
            command([publisher, "logout"], env, timeout=10)
        except Rejected:
            pass
        finally:
            try:
                credential.unlink(missing_ok=True)
                require(
                    not credential.exists() and not credential.is_symlink(),
                    "credential_cleanup_failed",
                )
                result["credential_cleanup"] = "removed"
            except OSError:
                raise Rejected("credential_cleanup_failed") from None


def write_json(path, value, *, exclusive=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
    with os.fdopen(os.open(path, flags, 0o600), "w") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    if exclusive:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def operate(environ, result):
    current = context(environ)
    result.update(
        {k: current[k] for k in ("repository", "id", "sha", "operation", "target_version")}
    )
    manifest_contract(json.loads(Path("server.json").read_text()), current)
    result["phase"] = "github_preflight"
    github_preflight(current, environ)  # Must pass before requesting OIDC.
    if "package_release" in current and current["operation"] in {"publish", "restore"}:
        result["phase"] = "pypi_preflight"
        result["pypi"] = pypi_preflight(current, environ)
    publisher = str(Path(environ["RUNNER_TEMP"]) / "mcp-publisher")
    result["phase"] = "authentication"
    with authenticated(publisher, current, environ, result):
        result["phase"] = "registry_preflight"
        result["before"] = before = snapshot()
        args = action(current, before)
        if args is None:
            result["after"] = snapshot()
            require(result["after"] == before, "registry_changed_without_mutation")
            result["status"] = "verified" if current["operation"] == "verify-identity" else "noop"
            return
        result["phase"] = "mutation"
        write_json(
            Path(environ["RUNNER_TEMP"]) / "registry-mutation-intent.json",
            {
                "operation": current["operation"],
                "target_version": current["target_version"],
                "sha": current["sha"],
                "before": before,
                "state": "may_have_been_applied_reconcile_before_another_attempt",
            },
            exclusive=True,
        )
        result["mutation_attempted"] = True
        command([publisher, *args], child_env(environ, oidc=True))  # Exactly one, never retried.
        result["phase"] = "postcondition"
        result["after"] = after = snapshot()
        changed = current["repository"]
        if current["operation"] in LEGACY_OPERATIONS:
            changed += "@" + current["target_version"]
        own = after[changed]
        expected = {
            "retire": "deleted",
            "deprecate-legacy": "deprecated",
        }.get(current["operation"], "active")
        require(own["status"] == expected, "postcondition_failed")
        if expected in {"deleted", "deprecated"}:
            message = (
                LEGACY_MESSAGE
                if expected == "deprecated"
                else RETIRE_MESSAGES[current["repository"]]
            )
            require(
                own["status_message_sha256"] == digest(message),
                "postcondition_failed",
            )
        require(
            all(after[r] == value for r, value in before.items() if r != changed),
            "counterpart_changed",
        )
        result["status"] = "completed"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "run"), default="run", nargs="?")
    args = parser.parse_args(argv)
    result = {
        "status": "error",
        "phase": "context",
        "identity_verified": False,
        "mutation_attempted": False,
        "credential_cleanup": "not_started",
    }
    path = Path(os.environ["RUNNER_TEMP"]) / "registry-result.json"
    try:
        write_json(path, result, exclusive=True)
    except OSError:
        print(json.dumps({"status": "error", "error": "result_already_exists_or_unwritable"}))
        return 1
    try:
        if args.command == "validate":
            _, selected = identity(os.environ)
            manifest_contract(json.loads(Path("server.json").read_text()), selected)
            fresh_credentials()  # validate may otherwise read a saved registry URL.
            command(
                [str(Path(os.environ["RUNNER_TEMP"]) / "mcp-publisher"), "validate", "server.json"],
                child_env(os.environ, oidc=True),
            )
            result.update(status="validated", phase="manifest_validation")
        else:
            operate(os.environ, result)
    except (Exception, KeyboardInterrupt) as error:
        result["status"] = "error"
        result["error"] = str(error) if isinstance(error, Rejected) else "operation_failed"
        result["reconciliation_required"] = result["mutation_attempted"]
    write_json(path, result)
    print(json.dumps(result, sort_keys=True))  # Only closed diagnostics and pinned public metadata.
    return 1 if result["status"] == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
