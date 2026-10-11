"""Published MCP guidance follows the actual catalog without dispatching writes."""

import json
import re
from contextlib import asynccontextmanager

import httpx
import pytest
from mcp import Client

from vt_mcp.reports import SHARING_NOTICE, report_http_error
from vt_mcp.server import create_report_server, create_server
from vt_mcp.vtai_client import Settings

pytestmark = pytest.mark.anyio
HASHES = ("a" * 32, "b" * 40, "c" * 64)
WEB_UPLOAD = "https://www.virustotal.com/gui/home/upload"


@pytest.mark.parametrize("surface", ["stdio", "remote", "read_only", "files_without_analysis"])
async def test_missing_file_guidance_uses_only_available_tools_and_keeps_read_contract(surface):
    calls = []

    def http(request):
        calls.append((request.method, request.url.path.rsplit("/", 1)[-1]))
        assert request.method == "GET", "A missing report must never submit or request an analysis"
        return httpx.Response(404, json={})

    class Missing:
        async def get_file_report(self, value):
            calls.append(("GET", value))
            # A reader may have inherited stdio suggestions; the catalog is authoritative.
            raise report_http_error(404, "file", interface="stdio")

    @asynccontextmanager
    async def lifespan(_):
        yield Missing()

    def forbidden(_):
        pytest.fail("Discovery and a missing report must not bind a submission/analysis reader")

    if surface == "stdio":
        server = create_server(Settings("synthetic-only"), transport=httpx.MockTransport(http))
    else:
        server = create_report_server(
            lifespan=lifespan,
            bind_reports=lambda context: context.request_context.lifespan_context,
            bind_submissions=forbidden if surface != "read_only" else None,
            bind_analyses=forbidden if surface == "remote" else None,
            bind_network_submissions=forbidden if surface == "remote" else None,
        )
    async with Client(server, mode="legacy") as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert len(client.instructions) < 2048
        assert SHARING_NOTICE in client.instructions
        assert WEB_UPLOAD in client.instructions
        assert "get_file_report(hash)" in client.instructions
        assert "not VTAI receipt or selected-analysis recovery" in client.instructions
        assert (
            len(names)
            == {"stdio": 11, "remote": 10, "read_only": 4, "files_without_analysis": 6}[surface]
        )
        if surface != "stdio":
            assert "submit_local_file" not in client.instructions
        for value in HASHES:
            result = await client.call_tool("get_file_report", {"hash": value})
            assert result.is_error and result.structured_content["status"] == "error"
            error = result.structured_content["error"]
            assert {key: error[key] for key in ("code", "http_status", "retryable")} == {
                "code": "not_found",
                "http_status": 404,
                "retryable": False,
            }
            assert set(error) == {
                "code",
                "message",
                "http_status",
                "retryable",
                "retry_after_seconds",
                "next_steps",
                "documentation_url",
            }
            steps = " ".join(error["next_steps"])
            assert "unknown" in steps and "Verify the hash" in steps
            assert "query quota" in steps
            assert WEB_UPLOAD not in steps
            assert not re.search(
                r"\b(?:submit_\w+|reanalyze_\w+|get_submission|get_analysis)\b", steps
            )
            assert value not in steps
            assert json.loads(result.content[0].text) == result.structured_content
    assert calls == [("GET", value) for value in HASHES]


async def test_guidance_does_not_offer_removed_local_or_recovery_tools():
    server = create_server(
        Settings("synthetic-only"), transport=httpx.MockTransport(lambda _: httpx.Response(404))
    )
    for name in ("submit_file", "get_analysis", "get_submission"):
        server.remove_tool(name)
    async with Client(server, mode="legacy") as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        result = await client.call_tool("get_file_report", {"hash": HASHES[0]})
        steps = " ".join(result.structured_content["error"]["next_steps"])
        mentioned = set(
            re.findall(r"\b(?:submit_(?:local_file|file)|get_(?:submission|analysis))\b", steps)
        )
        assert not mentioned
        assert "submit_local_file" in names


@pytest.mark.parametrize("status", [401, 403, 429, 503])
async def test_transfer_fallback_is_not_offered_for_access_quota_or_service_errors(status):
    calls = []

    def http(request):
        calls.append(request.method)
        return httpx.Response(status, json={})

    server = create_server(Settings("synthetic-only"), transport=httpx.MockTransport(http))
    async with Client(server, mode="legacy") as client:
        result = await client.call_tool("get_file_report", {"hash": HASHES[-1]})
        assert result.is_error
        error = result.structured_content["error"]
        assert error["http_status"] == status and error["code"] != "not_found"
        assert WEB_UPLOAD not in json.dumps(result.structured_content)
    assert calls == ["GET"]
