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

"""Pure, bounded presentation of actor-owned submissions and selected analyses."""

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from collections.abc import Generator
from contextlib import closing
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import quote

import anyio
from pydantic import BaseModel, ConfigDict, Field

from vt_mcp.reports import (
    MAX_RESPONSE_BYTES,
    VTAIError,
    format_file_report,
    validate_indicator,
    validate_report_values,
)

MAX_SUBMISSION_BYTES = 32_000_000
MAX_INLINE_SUBMISSION_BYTES = 24_000_000
MAX_INLINE_BASE64_CHARS = 4 * ((MAX_INLINE_SUBMISSION_BYTES + 2) // 3)
_BASE64_BLOCK_CHARS = 64 * 1024
MAX_ANALYSIS_ID_BYTES = 1024
SHA256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Count = Annotated[int, Field(ge=0)]
NetworkKind = Literal["url", "domain", "ip"]
_REQUEST_ID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
RequestID = Annotated[str, Field(pattern=f"^{_REQUEST_ID_PATTERN}$")]
_ERRORS = {
    "invalid_input": (422, "Invalid analysis or submission input", False),
    "sensitive_file": (
        422,
        "This attachment's filename may identify credentials. Stop for human review; "
        "do not rename it or use another upload path to bypass this check.",
        False,
    ),
    "consent_required": (422, "Explicit standard submission consent is required", False),
    "body_too_large": (413, "Submission exceeds 32000000 bytes", False),
    "inline_too_large": (
        413,
        "Inline submission exceeds 24000000 bytes. Use a local file or the VTAI binary "
        "submission channel for files up to 32000000 bytes.",
        False,
    ),
    "invalid_file": (
        422,
        "Provide a readable regular file within the submission size limit.",
        False,
    ),
    "snapshot_changed": (
        409,
        "The source changed while copying. No submission was started.",
        False,
    ),
    "snapshot_timeout": (504, "The local copy exceeded its preparation budget.", False),
    "local_state_unavailable": (
        503,
        "Durable private recovery state could not be confirmed. No POST was started.",
        False,
    ),
    "hash_mismatch": (422, "Submission bytes do not match the declared SHA256", False),
    "receipt_conflict": (409, "The existing submission receipt is incompatible", False),
    "not_found": (404, "No registered submission or analysis found", False),
    "rate_limited": (429, "VTAI or VirusTotal query quota exceeded", True),
    "contribution_limited": (
        429,
        "VTAI file contribution limit exceeded; wait before submitting another unknown file",
        True,
    ),
    "contribution_unavailable": (
        503,
        "File contribution admission is temporarily unavailable",
        True,
    ),
    "capacity_exceeded": (503, "Submission capacity is temporarily full", True),
    "invalid_response": (502, "Invalid VirusTotal analysis response", True),
    "response_too_large": (502, "Analysis response exceeds the supported size", True),
    "unavailable": (503, "Analysis service is temporarily unavailable", True),
    "timeout": (504, "Analysis operation timed out", True),
    "submission_unknown": (
        503,
        "Submission outcome is unknown; recover its receipt before taking further action",
        False,
    ),
    "access_denied": (403, "VTAI rejected this request. Check the credential and access.", False),
    "permission_denied": (403, "VirusTotal did not permit this analysis request.", False),
}
_NETWORK_REJECTIONS = {
    "invalid_input": "VirusTotal rejected this network indicator. "
    "Correct it and use a new request_id.",
    "permission_denied": "VirusTotal does not permit this network analysis. "
    "Do not retry unchanged.",
    "rate_limited": "VirusTotal rejected this network analysis because its quota is exhausted. "
    "Wait before using a new request_id.",
}


class AnalysisReader(Protocol):
    async def get_analysis(
        self, analysis_id: str, *, request_id: str | None = None
    ) -> dict[str, Any]: ...


class SubmissionReader(Protocol):
    async def submit_file(self, sha256: str, content_base64: str) -> dict[str, Any]: ...

    async def get_submission(self, sha256: str) -> dict[str, Any]: ...


class NetworkSubmissionReader(Protocol):
    async def submit_network(
        self, indicator_type: NetworkKind, indicator: str, request_id: str
    ) -> dict[str, Any]: ...

    async def get_network_submission(self, request_id: str) -> dict[str, Any]: ...


def validate_request_id(request_id: str) -> str:
    """Require the caller's retained canonical lowercase UUIDv4, without generating one."""
    if not isinstance(request_id, str) or not re.fullmatch(_REQUEST_ID_PATTERN, request_id):
        raise AnalysisError("invalid_input")
    return request_id


def validate_network_submission(indicator_type: str, indicator: str, request_id: str) -> None:
    validate_request_id(request_id)
    if not isinstance(indicator_type, str) or indicator_type not in {"url", "domain", "ip"}:
        raise AnalysisError("invalid_input")
    try:
        validate_indicator(indicator, indicator_type)
        if any(unicodedata.category(char).startswith("C") for char in indicator):
            raise AnalysisError("invalid_input")
    except VTAIError:
        raise AnalysisError("invalid_input") from None


class AnalysisError(VTAIError):
    def __init__(
        self,
        code: str,
        *,
        http_status: int | None = None,
        retry_after_seconds: int | None = None,
        submission: dict | None = None,
    ) -> None:
        code = code if code in _ERRORS else "invalid_response"
        status, message, retryable = _ERRORS[code]
        if type(retry_after_seconds) is not int or not 0 <= retry_after_seconds <= 9_999_999_999:
            retry_after_seconds = None
        super().__init__(
            code,
            message,
            retryable=retryable
            and not (isinstance(submission, dict) and submission.get("status") == "rejected"),
            http_status=http_status or status,
            retry_after_seconds=retry_after_seconds,
        )
        self.submission = submission


def analysis_http_error(
    status: int,
    *,
    code: str | None = None,
    retry_after_seconds: int | None = None,
    submission: dict | None = None,
) -> AnalysisError:
    """Use semantic HTTP status and a closed code, never a provider's message."""
    if status in (401, 403) and not (status == 403 and code == "permission_denied"):
        code = "access_denied"
    elif not isinstance(code, str) or code not in _ERRORS or _ERRORS[code][0] != status:
        code = {
            404: "not_found",
            409: "receipt_conflict",
            413: "body_too_large",
            422: "invalid_input",
            429: "rate_limited",
            502: "invalid_response",
            503: "unavailable",
            504: "timeout",
        }.get(status, "unavailable")
    if code not in {
        "rate_limited",
        "capacity_exceeded",
        "contribution_limited",
        "contribution_unavailable",
    } and not (code == "unavailable" and status == 503):
        retry_after_seconds = None
    return AnalysisError(
        code, http_status=status, retry_after_seconds=retry_after_seconds, submission=submission
    )


def validate_sha256(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise AnalysisError("invalid_input")
    return value


def _decode_submission_blocks(sha256: str, content_base64: str) -> Generator[bytes, None, None]:
    """Share validation/hash semantics without an uninterruptible whole-input decode."""
    validate_sha256(sha256)
    if not isinstance(content_base64, str):
        raise AnalysisError("invalid_input")
    if len(content_base64) > MAX_INLINE_BASE64_CHARS:
        raise AnalysisError("inline_too_large")
    if len(content_base64) % 4:
        raise AnalysisError("invalid_input")
    digest, size = hashlib.sha256(), 0
    for offset in range(0, len(content_base64), _BASE64_BLOCK_CHARS):
        block = content_base64[offset : offset + _BASE64_BLOCK_CHARS]
        if offset + len(block) < len(content_base64) and "=" in block:
            raise AnalysisError("invalid_input")
        try:
            decoded = base64.b64decode(block, validate=True)
        except (ValueError, binascii.Error):
            raise AnalysisError("invalid_input") from None
        size += len(decoded)
        if size > MAX_INLINE_SUBMISSION_BYTES:
            raise AnalysisError("inline_too_large")
        # Check canonical length/padding bits per quartet-aligned block. Only
        # the final block can contain padding; concatenated padded inputs fail.
        if len(block) != 4 * ((len(decoded) + 2) // 3) or (
            decoded
            and base64.b64encode(decoded[-(len(decoded) % 3 or 3) :]).decode("ascii") != block[-4:]
        ):
            raise AnalysisError("invalid_input")
        digest.update(decoded)
        yield decoded
    if digest.hexdigest() != sha256:
        raise AnalysisError("hash_mismatch")


def decode_submission(sha256: str, content_base64: str) -> bytes:
    """Synchronous canonical base64/SHA256 validation, retained for existing callers."""
    return b"".join(_decode_submission_blocks(sha256, content_base64))


async def decode_submission_async(sha256: str, content_base64: str) -> bytes:
    """Decode under the caller's deadline/capacity, with no detached thread.

    Each decode/hash step handles at most 64 KiB of ASCII base64. Cancellation
    checkpoints precede work, separate blocks, and follow the bounded final
    bytes assembly. No partial body is returned after cancellation or failure.
    """
    await anyio.lowlevel.checkpoint()
    parts = []
    with closing(_decode_submission_blocks(sha256, content_base64)) as blocks:
        for part in blocks:
            parts.append(part)
            await anyio.lowlevel.checkpoint()
    result = b"".join(parts)
    await anyio.lowlevel.checkpoint()
    return result


def _text(value: str, limit: int) -> None:
    if len(value) > limit or any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("Invalid text")


def validate_analysis_id(value: Any) -> str:
    try:
        if not isinstance(value, str) or not value or value in {".", ".."}:
            raise ValueError
        _text(value, MAX_ANALYSIS_ID_BYTES)
        if len(value.encode("utf-8")) > MAX_ANALYSIS_ID_BYTES or any(c.isspace() for c in value):
            raise ValueError
    except (ValueError, UnicodeError):
        raise AnalysisError("invalid_input") from None
    return value


def _bounded(raw: Any, forbidden_values: tuple[str, ...]) -> None:
    try:
        validate_report_values(raw, forbidden_values=forbidden_values)
        encoded = json.dumps(raw, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise AnalysisError("invalid_response") from None
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise AnalysisError("response_too_large")


def _utc(value: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", value):
        raise ValueError("Invalid UTC date")
    return datetime.fromisoformat(value)


class _Engine(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    engine_name: str | None = Field(None, max_length=512)
    engine_version: str | None = Field(None, max_length=256)
    engine_update: str | None = Field(None, max_length=64)
    category: str | None = Field(None, max_length=128)
    result: str | None = Field(None, max_length=4096)
    method: str | None = Field(None, max_length=128)


class _Coverage(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    engines: Count | None
    categories: list[str]


class _AnalysisEvidence(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    status: Literal["pending", "completed"]
    analysis_id: str
    analysis_status: Literal["queued", "in-progress", "completed"] | None
    source: Literal["VirusTotal via VTAI"]
    retrieved_at: str
    analysis_date: str | None
    stats: dict[str, Count] | None
    results: dict[str, _Engine] | None
    detections: list[str]
    coverage: _Coverage
    next_poll_after_seconds: Literal[5] | None
    pending_reason: Literal["processing", "not_available_yet", "result_not_ready"] | None


class _Analysis(_AnalysisEvidence):
    sha256: SHA256
    report_url: str


class _NetworkAnalysis(_AnalysisEvidence):
    request_id: RequestID
    indicator_type: NetworkKind
    report_id: str | None
    report_url: str | None


def _validate_network_report(data: _NetworkAnalysis) -> None:
    validate_request_id(data.request_id)
    if data.report_id is None:
        if data.report_url is not None or data.status == "completed":
            raise ValueError
        return
    if data.indicator_type == "url":
        if not re.fullmatch(r"[0-9a-f]{64}", data.report_id):
            raise ValueError
    else:
        validate_indicator(data.report_id, data.indicator_type)
    kind = "ip-address" if data.indicator_type == "ip" else data.indicator_type
    prefix = f"https://www.virustotal.com/gui/{kind}/"
    if data.report_url not in {prefix + quote(data.report_id, safe=""), prefix + data.report_id}:
        raise ValueError


def format_analysis_response(
    raw: Any,
    analysis_id: str,
    *,
    request_id: str | None = None,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Validate only the selected analysis. No I/O, current clock or latest report."""
    validate_analysis_id(analysis_id)
    if request_id is not None:
        validate_request_id(request_id)
    _bounded(raw, forbidden_values)
    try:
        network = isinstance(raw, dict) and bool({"request_id", "indicator_type"} & raw.keys())
        if network:
            if "sha256" in raw:
                raise ValueError
            data = _NetworkAnalysis.model_validate(raw)
            if request_id is not None and data.request_id != request_id:
                raise ValueError
            _validate_network_report(data)
        else:
            if request_id is not None:
                raise ValueError
            data = _Analysis.model_validate(raw)
            if data.report_url != f"https://www.virustotal.com/gui/file/{data.sha256}":
                raise ValueError
        if data.analysis_id != analysis_id:
            raise ValueError
        _utc(data.retrieved_at)
        if data.analysis_date is not None and _utc(data.analysis_date).timestamp() < 0:
            raise ValueError
        for key in data.stats or {}:
            _text(key, 128)
        categories, detections = set(), []
        for key, entry in (data.results or {}).items():
            _text(key, 512)
            for value in entry.model_dump().values():
                if value is not None:
                    _text(value, 4096)
            if entry.category is not None:
                categories.add(entry.category)
            if entry.result is not None:
                detections.append(entry.result)
        if (
            data.detections != detections
            or data.coverage.categories != sorted(categories)
            or data.coverage.engines != (len(data.results) if data.results is not None else None)
        ):
            raise ValueError
        if data.status == "completed":
            if (
                data.analysis_status != "completed"
                or data.stats is None
                or data.results is None
                or data.next_poll_after_seconds is not None
                or data.pending_reason is not None
            ):
                raise ValueError
        elif data.next_poll_after_seconds != 5:
            raise ValueError
        elif data.analysis_status is None:
            if (
                data.pending_reason != "not_available_yet"
                or data.stats is not None
                or data.results is not None
                or data.analysis_date is not None
            ):
                raise ValueError
        elif data.analysis_status == "completed":
            if (
                data.pending_reason != "result_not_ready"
                or data.stats is None
                or data.results is None
            ):
                raise ValueError
        elif data.pending_reason != "processing":
            raise ValueError
        result = data.model_dump()
    except (ValueError, TypeError, AttributeError, OverflowError, OSError, VTAIError):
        raise AnalysisError("invalid_response") from None
    _bounded(result, forbidden_values)
    return result


class _NetworkRejection(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    code: Literal["invalid_input", "permission_denied", "rate_limited"]
    message: str
    retryable: Literal[False]
    retry_after_seconds: int | None = Field(ge=0, le=99_999_999)


class _NetworkSubmission(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    status: Literal["submitted", "submission_unknown", "rejected"]
    mode: Literal["standard"]
    request_id: RequestID
    indicator_type: NetworkKind
    analysis_id: str | None
    analysis_status: None
    next_poll_after_seconds: Literal[5] | None
    can_resubmit: Literal[False]
    error: _NetworkRejection | None = None


def format_network_submission_response(
    raw: Any,
    request_id: str,
    *,
    indicator_type: NetworkKind | None = None,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    validate_request_id(request_id)
    _bounded(raw, forbidden_values)
    try:
        data = _NetworkSubmission.model_validate(raw)
        if (
            data.request_id != request_id
            or (indicator_type is not None and data.indicator_type != indicator_type)
            or raw["can_resubmit"] is not False
        ):
            raise ValueError
        if data.status == "submitted":
            validate_analysis_id(data.analysis_id)
            if data.next_poll_after_seconds != 5:
                raise ValueError
        elif data.analysis_id is not None or data.next_poll_after_seconds is not None:
            raise ValueError
        if data.status == "rejected":
            if data.error is None or raw["error"]["retryable"] is not False:
                raise ValueError
            data.error.message = _NETWORK_REJECTIONS[data.error.code]
        elif "error" in raw:
            raise ValueError
        result = data.model_dump(exclude={"error"} if data.error is None else set())
    except (ValueError, TypeError, KeyError, VTAIError):
        raise AnalysisError("invalid_response") from None
    _bounded(result, forbidden_values)
    return result


def unknown_network_submission(request_id: str, indicator_type: NetworkKind) -> dict[str, Any]:
    return {
        "status": "submission_unknown",
        "mode": "standard",
        "request_id": request_id,
        "indicator_type": indicator_type,
        "analysis_id": None,
        "analysis_status": None,
        "next_poll_after_seconds": None,
        "can_resubmit": False,
    }


class _Submission(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    status: Literal["submitted", "submission_unknown", "exists"]
    mode: Literal["standard"]
    submission_id: SHA256
    sha256: SHA256
    size: int = Field(ge=0, le=MAX_SUBMISSION_BYTES)
    analysis_id: str | None
    analysis_status: Literal["queued", "in-progress", "completed"] | None
    next_poll_after_seconds: Literal[5] | None
    can_resubmit: Literal[False]
    report: dict | None


def format_submission_response(
    raw: Any,
    sha256: str,
    *,
    size: int | None = None,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    validate_sha256(sha256)
    _bounded(raw, forbidden_values)
    try:
        data = _Submission.model_validate(raw)
        if (
            data.sha256 != sha256
            or data.submission_id != sha256
            or (size is not None and data.size != size)
            or raw["can_resubmit"] is not False
        ):
            raise ValueError
        if data.status == "submitted":
            validate_analysis_id(data.analysis_id)
            if (
                data.analysis_status is not None
                or data.next_poll_after_seconds != 5
                or data.report is not None
            ):
                raise ValueError
        else:
            if (
                data.analysis_id is not None
                or data.analysis_status is not None
                or data.next_poll_after_seconds is not None
            ):
                raise ValueError
            if data.status == "submission_unknown" and data.report is not None:
                raise ValueError
            if data.status == "exists":
                normalized = format_file_report(
                    data.report["data"],
                    sha256,
                    retrieved_at=datetime(1970, 1, 1, tzinfo=UTC),
                    forbidden_values=forbidden_values,
                )
                data.report = {"data": normalized["data"]}
        result = data.model_dump()
    except (ValueError, TypeError, KeyError, VTAIError):
        raise AnalysisError("invalid_response") from None
    _bounded(result, forbidden_values)
    return result


def unknown_submission(sha256: str, size: int) -> dict[str, Any]:
    return {
        "status": "submission_unknown",
        "mode": "standard",
        "submission_id": sha256,
        "sha256": sha256,
        "size": size,
        "analysis_id": None,
        "analysis_status": None,
        "next_poll_after_seconds": None,
        "can_resubmit": False,
        "report": None,
    }
