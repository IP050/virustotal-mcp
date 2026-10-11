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

"""Native files and exact installed-wheel stdio; synthetic bytes and loopback only."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import anyio
import pytest
from mcp import Client, StdioServerParameters

from vt_mcp import submission_cli as cli
from vt_mcp.vtai_client import Settings

TOKEN = "synthetic-native-submission-token"
BODY = b"Harmless binary fixture\r\n\x1a\x00" + bytes(range(256))
SHA = hashlib.sha256(BODY).hexdigest()
WINDOWS = pytest.mark.skipif(os.name != "nt", reason="Native Win32 API check")


def test_snapshot_preserves_binary_bytes_and_hash(tmp_path):
    path = tmp_path.resolve() / "input with spaces é ' & %.bin"
    path.write_bytes(BODY)
    with cli.copy_snapshot(str(path)) as snapshot:
        assert snapshot.size == len(BODY)
        assert snapshot.sha256 == SHA
        assert snapshot.file.read() == BODY


def test_reference_is_create_once_and_isolated_by_service_and_token(tmp_path):
    directory = tmp_path.resolve() / "state with spaces é"
    settings = Settings(TOKEN, "https://example.invalid/api/v3")
    assert cli.persist_reference(settings, SHA, directory) is True
    assert cli.persist_reference(settings, SHA, directory) is False
    assert cli.persist_reference(Settings(TOKEN + "2", settings.base_url), SHA, directory) is True
    assert (
        cli.persist_reference(Settings(TOKEN, "https://other.invalid/api/v3"), SHA, directory)
        is True
    )
    references = list(directory.rglob("*.json"))
    assert len(references) == 3
    assert all(TOKEN not in path.read_text() for path in references)


def test_stdio_inline_and_local_first_post_then_restart_get_only(tmp_path):
    directory = tmp_path.resolve() / "profile with spaces é ' & %"
    directory.mkdir()
    local = directory / "source.bin"
    local.write_bytes(BODY)
    credential_paths = []
    for name in (".env", "credentials.json", "id_rsa", "kubeconfig"):
        drive_relative = f"{directory.drive or 'C:'}{name}"
        fixture = directory / (name if os.name == "nt" else drive_relative)
        fixture.write_bytes(BODY)
        credential_paths.append(drive_relative)
    inline = BODY + b"inline fixture"
    inline_sha = hashlib.sha256(inline).hexdigest()
    expected = {SHA: BODY, inline_sha: inline}
    seen = []
    state = directory / "state"

    class Handler(BaseHTTPRequestHandler):
        def respond(self):
            sha = self.path.rsplit("/", 1)[-1]
            authorized = self.headers.get("x-apikey") == TOKEN
            valid = authorized and self.path == f"/api/v3/submissions/{sha}" and sha in expected
            body = None
            if self.command == "POST":
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                valid = valid and body == expected.get(sha)
                valid = valid and self.headers.get("x-vtai-consent") == "standard-v1"
                valid = valid and bool(list(state.rglob(sha + ".json")))
            seen.append((self.command, sha, bool(valid)))
            payload = (
                {
                    "status": "submitted",
                    "mode": "standard",
                    "submission_id": sha,
                    "sha256": sha,
                    "size": len(expected[sha]),
                    "analysis_id": "synthetic-analysis",
                    "analysis_status": None,
                    "next_poll_after_seconds": 5,
                    "can_resubmit": False,
                    "report": None,
                }
                if valid
                else {"error": "unexpected_synthetic_request"}
            )
            raw = json.dumps(payload).encode()
            self.send_response(200 if valid else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = respond
        do_POST = respond

        def log_message(self, *_):
            pass

    backend = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    async def session():
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-I", "-m", "vt_mcp"],
            cwd=directory,
            env={
                "VTAI_TOKEN": TOKEN,
                "XDG_STATE_HOME": str(state),
                "VTAI_BASE_URL": f"http://127.0.0.1:{backend.server_port}/api/v3",
            },
        )
        with anyio.fail_after(30):
            async with Client(parameters, read_timeout_seconds=15) as client:
                tools = {tool.name: tool for tool in (await client.list_tools()).tools}
                assert {"submit_file", "submit_local_file"} <= tools.keys()
                receipt = tools["get_submission"]
                assert receipt.annotations.model_dump(by_alias=True, exclude_none=True) == {
                    "title": "Get a VTAI submission receipt",
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                }
                assert set(receipt.input_schema["properties"]) == {"sha256", "request_id"}
                assert all(
                    tool.annotations.open_world_hint is True
                    for name, tool in tools.items()
                    if name != "get_submission"
                )
                references_before = sorted(state.rglob("*.json"))
                for path in credential_paths:
                    denied = await client.call_tool("submit_local_file", {"path": path})
                    assert denied.is_error is True
                    assert denied.structured_content["error"]["code"] == "invalid_file"
                assert sorted(state.rglob("*.json")) == references_before
                for _ in range(2):
                    for tool, arguments, sha in [
                        (
                            "submit_file",
                            {
                                "sha256": inline_sha,
                                "content_base64": base64.b64encode(inline).decode(),
                            },
                            inline_sha,
                        ),
                        ("submit_local_file", {"path": str(local), "expected_sha256": SHA}, SHA),
                    ]:
                        result = await client.call_tool(tool, arguments)
                        assert result.is_error is False
                        assert result.structured_content["status"] == "submitted"
                        assert result.structured_content["sha256"] == sha
                        assert result.structured_content["can_resubmit"] is False
                        assert TOKEN not in json.dumps(result.structured_content)

    try:
        anyio.run(session)
        anyio.run(session)  # A fresh process must recover the same durable references.
        assert seen == [
            ("POST", inline_sha, True),
            ("POST", SHA, True),
            ("GET", inline_sha, True),
            ("GET", SHA, True),
            ("GET", inline_sha, True),
            ("GET", SHA, True),
            ("GET", inline_sha, True),
            ("GET", SHA, True),
        ]
    finally:
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@WINDOWS
def test_windows_uncertain_flush_never_requalifies_for_post(tmp_path, monkeypatch):
    from vt_mcp.windows_files import WindowsFiles

    state = tmp_path.resolve() / "state"
    settings = Settings(TOKEN)
    original = WindowsFiles.flush

    def fail(_self, _fd):
        raise OSError("Synthetic flush failure")

    monkeypatch.setattr(WindowsFiles, "flush", fail)
    with pytest.raises(cli.CLIError) as failed:
        cli.persist_reference(settings, SHA, state)
    assert failed.value.code == "local_state_unavailable"
    assert len(list(state.rglob("*.json"))) == 1
    monkeypatch.setattr(WindowsFiles, "flush", original)
    assert cli.persist_reference(settings, SHA, state) is False


@WINDOWS
def test_windows_corrupt_reference_fails_closed(tmp_path):
    state = tmp_path.resolve() / "state"
    settings = Settings(TOKEN)
    assert cli.persist_reference(settings, SHA, state)
    reference = next(state.rglob("*.json"))
    reference.write_bytes(b"incomplete")
    with pytest.raises(cli.CLIError):
        cli.persist_reference(settings, SHA, state)
    assert reference.read_bytes() == b"incomplete"


@WINDOWS
def test_windows_concurrent_creators_qualify_at_most_once(tmp_path):
    state = tmp_path.resolve() / "state"

    def attempt(_):
        try:
            return cli.persist_reference(Settings(TOKEN), SHA, state)
        except cli.CLIError:
            return False  # A sharing conflict is fail-closed, never permission to retry a POST.

    with ThreadPoolExecutor(max_workers=4) as workers:
        assert list(workers.map(attempt, range(4))).count(True) == 1
    assert cli.persist_reference(Settings(TOKEN), SHA, state) is False


@WINDOWS
def test_windows_broad_receipt_acl_is_rejected(tmp_path):
    import ctypes as c
    from ctypes import wintypes as w

    from vt_mcp.windows_files import WindowsFiles

    state = tmp_path.resolve() / "state"
    assert cli.persist_reference(Settings(TOKEN), SHA, state)
    reference = next(state.rglob("*.json"))
    files, descriptor = WindowsFiles(), c.c_void_p()
    setter = files.advapi.SetFileSecurityW
    setter.restype, setter.argtypes = w.BOOL, [w.LPCWSTR, w.DWORD, c.c_void_p]
    assert files.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "D:P(A;;FA;;;WD)", 1, c.byref(descriptor), None
    )
    try:
        assert setter(str(reference), 0x4 | 0x80000000, descriptor)
    finally:
        files.kernel.LocalFree(descriptor)
    with pytest.raises(cli.CLIError):
        cli.persist_reference(Settings(TOKEN), SHA, state)


@WINDOWS
def test_windows_reparse_parent_blocks_state_and_snapshot(tmp_path):
    root = tmp_path.resolve()
    target, junction = root / "real", root / "junction"
    target.mkdir()
    (target / "source.bin").write_bytes(BODY)

    def quote(path):
        return "'" + str(path).replace("'", "''") + "'"

    script = (
        "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path "
        + quote(junction)
        + " -Target "
        + quote(target)
        + " | Out-Null"
    )
    command = base64.b64encode(script.encode("utf-16le")).decode()
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
        capture_output=True,
        check=True,
        timeout=15,
    )
    try:
        with pytest.raises(cli.CLIError):
            cli.persist_reference(Settings(TOKEN), SHA, junction / "state")
        with pytest.raises(cli.CLIError), cli.copy_snapshot(str(junction / "source.bin")):
            pytest.fail("A junction must not be traversed")
        assert not (target / "state").exists()
    finally:
        junction.rmdir()


@WINDOWS
def test_windows_source_symlink_is_not_followed(tmp_path):
    source, link = tmp_path.resolve() / "source.bin", tmp_path.resolve() / "link.bin"
    source.write_bytes(BODY)
    try:
        link.symlink_to(source)
    except OSError as error:
        if error.winerror == 1314:
            pytest.skip("Windows account lacks symbolic-link creation privilege")
        raise
    with pytest.raises(cli.CLIError), cli.copy_snapshot(str(link)):
        pytest.fail("A source symbolic link must not be followed")


@WINDOWS
def test_windows_hard_linked_reference_is_rejected(tmp_path):
    state = tmp_path.resolve() / "state"
    assert cli.persist_reference(Settings(TOKEN), SHA, state)
    reference = next(state.rglob("*.json"))
    os.link(reference, tmp_path.resolve() / "second-link.json")
    with pytest.raises(cli.CLIError):
        cli.persist_reference(Settings(TOKEN), SHA, state)
