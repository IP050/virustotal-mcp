# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Host file metadata stays bounded and never enables a downloader in local stdio."""

import json
from contextlib import asynccontextmanager

import httpx
import pytest
from analysis_helpers import SHA, TOKEN, submission_response
from mcp import Client

from vt_mcp.analyses import AnalysisError
from vt_mcp.reports import VTAIError
from vt_mcp.server import create_report_server, create_server
from vt_mcp.vtai_client import Settings

pytestmark = pytest.mark.anyio
FILE = {
    "download_url": "https://files.example.invalid/fixture?sig=private",
    "file_id": "file_fixture",
}


@asynccontextmanager
async def lifespan(_):
    yield None


def never(_):
    pytest.fail("Discovery or invalid arguments must not bind a reader")


def server(binding=never):
    return create_report_server(
        lifespan=lifespan,
        bind_reports=never,
        bind_analyses=never,
        bind_submissions=never,
        bind_network_submissions=never,
        bind_attachment_submissions=binding,
    )


async def test_file_descriptor_has_neutral_shape_and_native_file_metadata_and_write_annotations():
    async with Client(server()) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "submit_attachment")
        assert len(client.instructions) < 2048
    schema = tool.input_schema
    shape = schema["$defs"][schema["properties"]["file"]["$ref"].split("/")[-1]]
    assert schema["required"] == ["file"] and set(schema["properties"]) == {"file"}
    assert shape["required"] == ["download_url"]
    assert shape["title"] == "AttachmentFile"
    assert shape["additionalProperties"] is False
    assert set(shape["properties"]) == {"download_url", "file_id", "mime_type", "file_name"}
    assert all(
        field["type"] == "string" and "anyOf" not in field for field in shape["properties"].values()
    )
    wire = tool.model_dump(by_alias=True, exclude_none=True)
    assert wire["_meta"] == {"openai/fileParams": ["file"]}
    assert wire["annotations"] == {
        "title": "Submit an attachment to VirusTotal",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    }


async def test_no_attachment_tool_in_read_only_hosts_or_local_stdio():
    for instance in [
        create_report_server(lifespan=lifespan, bind_reports=never),
        create_server(
            Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("HTTP"))
        ),
    ]:
        async with Client(instance) as client:
            assert "submit_attachment" not in {
                tool.name for tool in (await client.list_tools()).tools
            }


@pytest.mark.parametrize("bindings", [{}, {"bind_submissions": never}, {"bind_analyses": never}])
def test_host_must_supply_receipt_and_analysis_recovery(bindings):
    with pytest.raises(ValueError, match="file receipts and analysis reads"):
        create_report_server(
            lifespan=lifespan, bind_reports=never, bind_attachment_submissions=never, **bindings
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"file": None},
        {"file": FILE, "other": FILE["download_url"]},
        {"file": {"file_id": "file_fixture"}},
        {"file": {**FILE, "download_url": "http://files.example.invalid/a"}},
        {"file": {**FILE, "download_url": "file:///tmp/a"}},
        {"file": {**FILE, "download_url": "https://user:secret@example.com/a"}},
        {"file": {**FILE, "download_url": "https://example.com:invalid/a"}},
        {"file": {**FILE, "download_url": "https://example.com/a#fragment"}},
        {"file": {**FILE, "download_url": "https://example.com/a b"}},
        {"file": {**FILE, "mime_type": None}},
        {"file": {**FILE, "file_name": 1}},
        {"file": {**FILE, "file_id": ""}},
        {"file": {**FILE, "file_id": "x" * 257}},
        {"file": {**FILE, "download_url": "x" * 8193}},
        {"file": {**FILE, "file_name": "x" * 256}},
        {"file": {**FILE, "mime_type": "x" * 256}},
        {"file": {**FILE, "file_name": "line\nsecret"}},
        {"file": {**FILE, "file_id": "file\x00secret"}},
        {"file": {**FILE, "extra": FILE["download_url"]}},
    ],
)
async def test_invalid_input_is_closed_before_binding_or_sdk_error_echo(arguments):
    async with Client(server()) as client:
        result = await client.call_tool("submit_attachment", arguments)
    assert result.is_error
    assert result.structured_content["error"]["code"] == "invalid_input"
    assert FILE["download_url"] not in result.content[0].text
    assert "input_value" not in result.content[0].text


async def test_optional_fields_are_preserved_and_binding_is_per_call_with_actual_sha():
    seen = []
    bound = []

    class Reader:
        async def submit_attachment(self, file):
            seen.append(file)
            return submission_response()

    def bind(ctx):
        bound.append(ctx)
        return Reader()

    async with Client(server(bind)) as client:
        for file in [
            {"download_url": "https://research.example.org/original-sample.bin"},
            FILE,
            {**FILE, "file_name": "public.bin", "mime_type": "application/octet-stream"},
            {**FILE, "file_name": "", "mime_type": ""},
        ]:
            result = await client.call_tool("submit_attachment", {"file": file})
            assert not result.is_error and result.structured_content == submission_response()
            assert FILE["download_url"] not in result.content[0].text
    assert seen == [
        {"download_url": "https://research.example.org/original-sample.bin"},
        FILE,
        {**FILE, "file_name": "public.bin", "mime_type": "application/octet-stream"},
        {**FILE, "file_name": "", "mime_type": ""},
    ]
    assert len(bound) == 4


@pytest.mark.parametrize("mode", ["unknown", "exception", "echo", "fixed_download_error"])
async def test_failure_recovery_and_signed_url_sanitization(mode):
    class Reader:
        async def submit_attachment(self, _):
            if mode == "unknown":
                raise AnalysisError(
                    "submission_unknown",
                    submission=submission_response(status="submission_unknown"),
                )
            if mode == "exception":
                raise RuntimeError(FILE["download_url"])
            if mode == "echo":
                raise VTAIError("download_failed", FILE["download_url"])
            raise VTAIError("download_unavailable", "Request a fresh attachment link.")

    async with Client(server(lambda _: Reader())) as client:
        result = await client.call_tool("submit_attachment", {"file": FILE})
    assert result.is_error
    assert FILE["download_url"] not in json.dumps(result.model_dump())
    if mode == "unknown":
        assert result.structured_content["submission"]["sha256"] == SHA
        assert result.structured_content["error"]["retryable"] is False
    elif mode == "echo":
        assert result.structured_content["error"]["code"] == "invalid_response"
    elif mode == "fixed_download_error":
        assert result.structured_content["error"]["message"] == "Request a fresh attachment link."


async def test_missing_report_never_suggests_an_attachment_submission():
    class Reports:
        async def get_file_report(self, _):
            raise VTAIError("not_found", "Unknown file", http_status=404)

    instance = create_report_server(
        lifespan=lifespan,
        bind_reports=lambda _: Reports(),
        bind_analyses=never,
        bind_submissions=never,
        bind_attachment_submissions=never,
    )
    async with Client(instance) as client:
        result = await client.call_tool("get_file_report", {"hash": SHA})
    assert result.is_error
    steps = " ".join(result.structured_content["error"]["next_steps"])
    assert "unknown" in steps and "Verify the hash" in steps
    assert "submit_attachment" not in steps and "submit_file" not in steps
    assert "https://www.virustotal.com/gui/home/upload" not in steps


@pytest.mark.parametrize("raw", [None, {}, {"sha256": "not-a-sha256"}])
async def test_invalid_download_result_is_not_a_submission_receipt(raw):
    class Reader:
        async def submit_attachment(self, _):
            return raw

    async with Client(server(lambda _: Reader())) as client:
        result = await client.call_tool("submit_attachment", {"file": FILE})
    assert result.is_error and result.structured_content["error"]["code"] == "invalid_response"
    assert "submission" not in result.structured_content


@pytest.mark.parametrize(
    "filename",
    [
        "id_rsa",
        ".env",
        "private.pfx",
        "C:\\Users\\you\\credentials.json",
        "C:credentials.json",
        "c:.env",
        "/home/you/.npmrc",
    ],
)
async def test_sensitive_filename_denied_before_binding_with_actionable_closed_error(filename):
    async with Client(server()) as client:
        result = await client.call_tool(
            "submit_attachment", {"file": {**FILE, "file_name": filename}}
        )
    assert result.is_error
    error = result.structured_content["error"]
    assert error["code"] == "sensitive_file" and error["http_status"] == 422
    assert error["retryable"] is False
    assert "Stop for human review" in error["message"]
    assert "do not rename" in error["message"]
    assert filename not in json.dumps(result.model_dump())
    assert FILE["download_url"] not in json.dumps(result.model_dump())


@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_complete_discovery_and_instructions_are_client_neutral(mode):
    async with Client(server(), mode=mode) as client:
        tools = (await client.list_tools()).tools
        names = {tool.name for tool in tools}
        assert names == {
            "get_file_report",
            "get_url_report",
            "get_domain_report",
            "get_ip_report",
            "get_analysis",
            "get_submission",
            "submit_file",
            "submit_attachment",
            "submit_url",
            "reanalyze_domain",
            "reanalyze_ip",
        }
        handshake = (
            client.session.initialize_result if mode == "legacy" else client.session.discover_result
        )
        assert handshake is not None
        wire = json.dumps(handshake.model_dump(by_alias=True, exclude_none=True))
        wire += json.dumps([tool.model_dump(by_alias=True, exclude_none=True) for tool in tools])
        assert "chatgpt" not in wire.lower()
        assert "Submit unfamiliar" not in wire and "Submit suspicious" not in wire
        assert "user explicitly" in client.instructions
        assert all(tool.annotations.title == tool.title for tool in tools)
        assert len({tool.annotations.title for tool in tools}) == len(tools)
        for tool in tools:
            if not tool.annotations.read_only_hint:
                assert "user explicitly requests" in tool.description
        legacy = await client.call_tool("submit_chatgpt_file", {"file": FILE})
        assert legacy.is_error
