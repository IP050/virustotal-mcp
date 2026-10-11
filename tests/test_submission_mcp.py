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

"""Submission tool contracts through the SDK, with inert local transports only."""

import asyncio
import base64
import hashlib
import json
from contextlib import asynccontextmanager

import anyio
import httpx
import pytest
from analysis_helpers import BODY, SHA, TOKEN, submission_response
from mcp import Client

from vt_mcp.analyses import AnalysisError, decode_submission
from vt_mcp.server import create_report_server, create_server
from vt_mcp.vtai_client import Settings

pytestmark = pytest.mark.anyio
ENCODED = base64.b64encode(BODY).decode()
READ_TOOLS = {"get_file_report", "get_url_report", "get_domain_report", "get_ip_report"}


@asynccontextmanager
async def lifespan(_):
    yield None


@pytest.mark.parametrize(
    "analysis,submission,count", [(False, False, 4), (True, False, 5), (True, True, 7)]
)
async def test_optional_binder_compatibility_and_submission_schemas(analysis, submission, count):
    def never(_):
        pytest.fail("Discovery must not bind a reader")

    server = create_report_server(
        lifespan=lifespan,
        bind_reports=never,
        bind_analyses=never if analysis else None,
        bind_submissions=never if submission else None,
    )
    async with Client(server) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert len(tools) == count and "submit_local_file" not in tools
    assert READ_TOOLS <= tools.keys()
    if submission:
        assert set(tools["submit_file"].input_schema["properties"]) == {"sha256", "content_base64"}
        assert (
            tools["submit_file"].input_schema["properties"]["content_base64"]["maxLength"]
            == 32_000_000
        )
        assert not tools["submit_file"].annotations.read_only_hint
        assert not tools["submit_file"].annotations.idempotent_hint
        assert set(tools["get_submission"].input_schema["properties"]) == {"sha256"}
        assert tools["get_submission"].annotations.read_only_hint
        assert tools["get_submission"].annotations.idempotent_hint


@pytest.mark.parametrize("file,network", [(True, False), (False, True), (True, True)])
async def test_receipt_discovery_is_bounded_for_each_submission_binding(file, network):
    def never(_):
        pytest.fail("Discovery must not bind a reader")

    server = create_report_server(
        lifespan=lifespan,
        bind_reports=never,
        bind_analyses=never,
        bind_submissions=never if file else None,
        bind_network_submissions=never if network else None,
    )
    async with Client(server) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    receipt = tools["get_submission"]
    assert receipt.annotations.model_dump(by_alias=True, exclude_none=True) == {
        "title": "Get a VTAI submission receipt",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    assert set(receipt.input_schema["properties"]) == (
        {"sha256", "request_id"} if network else {"sha256"}
    )
    assert receipt.input_schema.get("required", []) == ([] if network else ["sha256"])
    assert all(
        tool.annotations.open_world_hint is True
        for name, tool in tools.items()
        if name != "get_submission"
    )


async def test_local_has_eleven_tools_and_no_confirmation_argument():
    server = create_server(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("Discovery HTTP"))
    )
    async with Client(server) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert len(tools) == 11
    local = tools["submit_local_file"]
    assert set(local.input_schema["properties"]) == {"path", "expected_sha256"}
    assert local.input_schema["required"] == ["path"]
    assert not local.annotations.read_only_hint and not local.annotations.idempotent_hint


async def test_sdk_inline_size_boundary_uses_exact_raw_http_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    body = b"x" * 24_000_000
    digest = hashlib.sha256(body).hexdigest()
    seen = []

    async def handler(request):
        raw = await request.aread()
        seen.append((request.method, len(raw), hashlib.sha256(raw).hexdigest()))
        return httpx.Response(200, json=submission_response(digest, len(raw)))

    server = create_server(Settings(TOKEN), transport=httpx.MockTransport(handler))
    async with Client(server) as client:
        result = await client.call_tool(
            "submit_file", {"sha256": digest, "content_base64": base64.b64encode(body).decode()}
        )
        assert not result.is_error and result.structured_content["size"] == len(body)
        too_large = await client.call_tool(
            "submit_file", {"sha256": digest, "content_base64": "A" * 32_000_004}
        )
    assert too_large.is_error
    assert too_large.structured_content["error"]["code"] == "inline_too_large"
    assert seen == [("POST", 24_000_000, digest)]


@pytest.mark.parametrize(
    "tool,args",
    [
        ("submit_file", {}),
        ("submit_file", {"sha256": SHA}),
        ("submit_file", {"sha256": SHA, "content_base64": 1}),
        ("submit_file", {"sha256": "bad", "content_base64": ENCODED}),
        ("submit_file", {"sha256": SHA, "content_base64": ENCODED, "token": TOKEN}),
        ("submit_file", {"sha256": SHA, "content_base64": ENCODED, "confirm": True}),
        ("get_submission", {"sha256": []}),
        ("get_submission", {"sha256": SHA, "url": TOKEN}),
        ("submit_local_file", {"path": TOKEN, "expected_sha256": []}),
        ("submit_local_file", {"path": TOKEN, "consent": True}),
        ("submit_local_file", {"path": "\x00"}),
        ("submit_local_file", {"path": 1}),
    ],
)
async def test_malformed_arguments_never_bind_or_expose_inputs(tool, args):
    def never(_):
        pytest.fail("Invalid shape bound a reader")

    server = create_report_server(lifespan=lifespan, bind_reports=never, bind_submissions=never)
    async with Client(server) as client:
        result = await client.call_tool(tool, args)
    assert result.is_error and result.structured_content["error"]["code"] == "invalid_input"
    assert TOKEN not in result.content[0].text and "input_value" not in result.content[0].text


@pytest.mark.parametrize("mode", ["lost", "secret", "malformed", "rejected"])
async def test_submission_error_retains_safe_recovery_and_never_retries(
    mode, tmp_path, monkeypatch, caplog
):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(404)
        if mode == "lost":
            raise httpx.ReadTimeout(TOKEN)
        if mode == "malformed":
            return httpx.Response(200, content=b"{broken-json")
        if mode == "rejected":
            return httpx.Response(429, json={"detail": {"message": TOKEN, "code": "rate_limited"}})
        return httpx.Response(200, json={**submission_response(), "unexpected": TOKEN})

    server = create_server(Settings(TOKEN), transport=httpx.MockTransport(handler))
    async with Client(server) as client:
        result = await client.call_tool("submit_file", {"sha256": SHA, "content_base64": ENCODED})
        assert result.is_error
        assert result.structured_content["error"]["code"] == (
            "rate_limited" if mode == "rejected" else "submission_unknown"
        )
        assert result.structured_content["submission"] == submission_response(
            status="submission_unknown"
        )
        second = await client.call_tool("submit_file", {"sha256": SHA, "content_base64": ENCODED})
    assert second.is_error and second.structured_content["error"]["code"] == "not_found"
    assert second.structured_content["submission"] == result.structured_content["submission"]
    assert calls == ["POST", "GET"]
    assert TOKEN not in result.content[0].text + second.content[0].text + caplog.text
    assert json.loads(result.content[0].text) == result.structured_content


@pytest.mark.parametrize("receipt", ["valid_extra", "wrong_sha", "invalid_status", "bad_shape"])
async def test_bound_error_receipt_is_minimized_and_validated(receipt):
    raw = submission_response(status="submission_unknown")
    raw["unexpected"] = TOKEN
    if receipt == "wrong_sha":
        raw["sha256"] = raw["submission_id"] = "0" * 64
    elif receipt == "invalid_status":
        raw["status"] = TOKEN
    elif receipt == "bad_shape":
        raw = [TOKEN]

    class Reader:
        async def submit_file(self, sha256, content_base64):
            raise AnalysisError("submission_unknown", submission=raw)

    server = create_report_server(
        lifespan=lifespan, bind_reports=lambda _: None, bind_submissions=lambda _: Reader()
    )
    async with Client(server) as client:
        result = await client.call_tool("submit_file", {"sha256": SHA, "content_base64": ENCODED})
    assert result.is_error and TOKEN not in result.content[0].text
    assert result.structured_content["error"]["code"] == (
        "submission_unknown" if receipt == "valid_extra" else "invalid_response"
    )
    if receipt == "valid_extra":
        assert result.structured_content["submission"] == submission_response(
            status="submission_unknown"
        )


@pytest.mark.parametrize("protocol", ["2025-11-25", "2026-07-28"])
async def test_http_concurrent_submission_binders_keep_actors_separate(protocol):
    entered, bindings = [], []
    ready = anyio.Event()

    class Reader:
        def __init__(self, actor):
            self.actor = actor

        async def submit_file(self, sha256, content_base64):
            assert decode_submission(sha256, content_base64) == BODY
            entered.append(self.actor)
            if len(entered) == 2:
                ready.set()
            with anyio.fail_after(3):
                await ready.wait()
            return {**submission_response(), "analysis_id": self.actor}

    def bind(ctx):
        actor = getattr(ctx.request_context.request.state, "actor", None)
        if actor is None:
            raise AnalysisError("access_denied")
        bindings.append(actor)
        return Reader(actor)

    server = create_report_server(
        lifespan=lifespan, bind_reports=lambda _: None, bind_submissions=bind
    )
    child = server.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=True, json_response=True
    )

    async def fixture(scope, receive, send):
        actor = dict(scope.get("headers", [])).get(b"x-fixture-actor")
        state = {"actor": actor.decode()} if actor in {b"alice", b"bob"} else {}
        await child({**scope, "state": state}, receive, send)

    async with (
        server.session_manager.run(),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fixture), base_url="http://localhost:8000"
        ) as client,
    ):

        async def submit(actor):
            headers = {
                "accept": "application/json, text/event-stream",
                "mcp-protocol-version": protocol,
            }
            if actor:
                headers["x-fixture-actor"] = actor
            params = {
                "name": "submit_file",
                "arguments": {"sha256": SHA, "content_base64": ENCODED},
            }
            if protocol == "2026-07-28":
                headers.update({"mcp-method": "tools/call", "mcp-name": "submit_file"})
                params["_meta"] = {
                    "io.modelcontextprotocol/protocolVersion": protocol,
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            return await client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": actor or "none",
                    "method": "tools/call",
                    "params": params,
                },
            )

        responses = await asyncio.gather(submit("alice"), submit("bob"))
        for actor, response in zip(("alice", "bob"), responses, strict=True):
            assert response.status_code == 200
            assert response.json()["result"]["structuredContent"]["analysis_id"] == actor
        missing = await submit(None)
        assert missing.json()["result"]["structuredContent"]["error"]["code"] == "access_denied"
    assert bindings == entered == ["alice", "bob"]
