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

"""Actionable errors remain bounded, private and free of implicit write retries."""

import base64
import io
import json
from datetime import UTC, datetime

import httpx
import pytest
from analysis_helpers import ANALYSIS_ID, BODY, SHA, TOKEN
from mcp import Client

from vt_mcp.analyses import AnalysisError, analysis_http_error
from vt_mcp.client import AnalysisClient
from vt_mcp.reports import VTAIError, parse_retry_after, report_http_error
from vt_mcp.server import create_server
from vt_mcp.vtai_client import Settings, VTAIClient


@pytest.mark.anyio
@pytest.mark.parametrize("interface", ["http", "mcp"])
@pytest.mark.parametrize(
    "status,code",
    [(429, "contribution_limited"), (503, "contribution_unavailable")],
)
async def test_file_contribution_errors_are_distinct_bounded_and_not_replayed(
    interface, status, code, tmp_path, monkeypatch
):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    calls = []

    async def handler(request):
        calls.append((request.method, await request.aread()))
        if request.method == "GET":
            return httpx.Response(404)
        return httpx.Response(
            status,
            headers={"Retry-After": "17"},
            json={"detail": {"code": code, "message": TOKEN, "retry_after_seconds": 23}},
        )

    transport = httpx.MockTransport(handler)
    if interface == "http":
        async with AnalysisClient(Settings(TOKEN), transport=transport) as client:
            with pytest.raises(AnalysisError) as caught:
                await client.submit(io.BytesIO(BODY), SHA, len(BODY))
        error = caught.value.error
        assert calls == [("POST", BODY)]
    else:
        server = create_server(Settings(TOKEN), transport=transport)
        args = {"sha256": SHA, "content_base64": base64.b64encode(BODY).decode()}
        async with Client(server) as client:
            result = await client.call_tool("submit_file", args)
            assert result.is_error
            error = result.structured_content["error"]
            # The existing durable reference still forbids implicit POST replay.
            recovery = await client.call_tool("submit_file", args)
        assert recovery.is_error
        assert recovery.structured_content["error"]["code"] == "not_found"
        assert calls == [("POST", BODY), ("GET", b"")]
    assert error["code"] == code and error["http_status"] == status
    assert error["retry_after_seconds"] == 17
    assert "contribution" in error["message"].lower()
    assert "query quota" not in error["message"].lower()
    assert TOKEN not in json.dumps(error)


@pytest.mark.parametrize(
    "status,code,expected",
    [
        (503, "contribution_limited", "unavailable"),
        (429, "contribution_unavailable", "rate_limited"),
        (403, "contribution_limited", "access_denied"),
    ],
)
def test_contribution_codes_cannot_override_http_status(status, code, expected):
    assert analysis_http_error(status, code=code).error["code"] == expected


@pytest.mark.parametrize("interface", ["remote", "stdio", "rest"])
def test_missing_file_keeps_recovery_read_only(interface):
    error = report_http_error(404, "file", interface=interface).error
    steps = " ".join(error["next_steps"])
    assert error["code"] == "not_found" and error["retryable"] is False
    assert "does not establish safety" in error["message"]
    assert "Verify the hash" in steps and "unknown" in steps
    assert "query quota" in steps
    for forbidden in ("submit_file", "submit_local_file", "submit_attachment", "POST", "/upload"):
        assert forbidden not in steps
    assert error["documentation_url"] == "https://ai.virustotal.com/install.md"
    assert "quota_source" not in error


@pytest.mark.parametrize("interface", ["remote", "stdio", "rest"])
@pytest.mark.parametrize("kind", ["url", "domain", "ip"])
def test_missing_indicators_remain_read_only_without_transferring_domain_safety(interface, kind):
    error = report_http_error(404, kind, interface=interface).error
    steps = " ".join(error["next_steps"])
    assert "https://www.virustotal.com/gui/home/upload" not in steps
    assert "retrieves existing reports" in steps or "retrieve existing reports" in steps
    assert "submit_file" not in steps
    assert "unknown" in steps and "Verify the indicator" in steps
    for forbidden in ("submit_url", "reanalyze_domain", "reanalyze_ip", "POST", "request_id"):
        assert forbidden not in steps
    if kind == "url":
        assert "does not establish the URL's safety" in steps
        assert (
            "GET /api/v3/domains/{domain}" if interface == "rest" else "get_domain_report"
        ) in steps


@pytest.mark.parametrize("value", [None, True, -1, "-1", "1.5", "100000000", "9" * 100, [], "17\n"])
def test_retry_header_invalid_values_are_not_a_delay(value):
    assert parse_retry_after(value) is None


@pytest.mark.parametrize("status", [401, 403, 422, 502, 504, 307])
def test_other_errors_keep_the_existing_shape(status):
    assert set(report_http_error(status, "file").error) == {
        "code",
        "message",
        "retryable",
        "http_status",
        "retry_after_seconds",
    }


def test_unrecognized_interface_and_quota_source_do_not_escape_the_closed_contract():
    assert (
        report_http_error(404, "file", interface=[]).error == report_http_error(404, "file").error
    )
    assert report_http_error(429, "file", quota_source=["actor"]).error["quota_source"] == "unknown"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "source,expected",
    [
        ("actor", "actor"),
        ("upstream", "upstream"),
        ("unknown", "unknown"),
        (TOKEN, "unknown"),
        ({"private": TOKEN}, "unknown"),
        (["actor"], "unknown"),
    ],
)
async def test_report_quota_source_is_closed_and_never_uses_provider_messages(source, expected):
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(
            429,
            headers={"Retry-After": "17"},
            json={"detail": {"quota_source": source, "message": TOKEN, "next_steps": [TOKEN]}},
        )

    async with VTAIClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_domain_report("example.com")
    error = caught.value.error
    assert error["quota_source"] == expected and error["retry_after_seconds"] == 17
    assert TOKEN not in json.dumps(error)
    assert calls == ["GET"]


@pytest.mark.anyio
async def test_mcp_structured_error_contains_recovery_without_starting_a_submission():
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(404, json={"detail": TOKEN})

    server = create_server(Settings(TOKEN), transport=httpx.MockTransport(handler))
    async with Client(server) as client:
        result = await client.call_tool("get_file_report", {"hash": SHA})
    assert result.is_error
    error = result.structured_content["error"]
    assert error["code"] == "not_found"
    assert "submit_local_file" not in " ".join(error["next_steps"])
    assert calls == ["GET"] and TOKEN not in json.dumps(error)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "status,code,header,expected",
    [
        (429, "rate_limited", "17", 17),
        (503, "capacity_exceeded", "17", 17),
        (503, "unavailable", "Sun, 06 Sep 2026 12:02:00 GMT", 120),
        (503, "unavailable", "invalid-private-delay", 23),
    ],
)
async def test_analysis_read_preserves_header_delay_then_legacy_body_fallback(
    monkeypatch, status, code, header, expected
):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 6, 12, 0, 0, 250000, tzinfo=UTC)

    monkeypatch.setattr("vt_mcp.reports.datetime", Clock)
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(
            status,
            headers={"Retry-After": header},
            json={"detail": {"code": code, "retry_after_seconds": 23, "message": TOKEN}},
        )

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(AnalysisError) as caught:
            await client.get_analysis(ANALYSIS_ID)
    assert caught.value.error["retry_after_seconds"] == expected
    assert TOKEN not in json.dumps(caught.value.error) and calls == ["GET"]


@pytest.mark.anyio
async def test_submission_503_with_delay_remains_unknown_and_is_not_replayed():
    calls = []

    async def handler(request):
        calls.append((request.method, await request.aread()))
        return httpx.Response(
            503,
            headers={"Retry-After": "17"},
            json={"detail": {"code": "unavailable", "retry_after_seconds": 23}},
        )

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(AnalysisError) as caught:
            await client.submit(io.BytesIO(BODY), SHA, len(BODY))
    assert caught.value.error["code"] == "submission_unknown"
    assert caught.value.error["retryable"] is False
    assert caught.value.error["retry_after_seconds"] is None
    assert caught.value.submission["can_resubmit"] is False
    assert calls == [("POST", BODY)]
    assert (
        analysis_http_error(503, code="local_state_unavailable", retry_after_seconds=17).error[
            "retry_after_seconds"
        ]
        is None
    )
