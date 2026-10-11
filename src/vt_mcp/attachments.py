# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Client-neutral attachment shape; the authorized host owns fetching and submission."""

import unicodedata
from typing import Annotated, NotRequired, Protocol, TypedDict
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field

from vt_mcp.analyses import AnalysisError
from vt_mcp.client_contracts import credential_filename_denied


class AttachmentFile(TypedDict):
    __pydantic_config__ = ConfigDict(extra="forbid", strict=True)

    download_url: Annotated[str, Field(min_length=1, max_length=8192)]
    file_id: NotRequired[Annotated[str, Field(min_length=1, max_length=256)]]
    mime_type: NotRequired[Annotated[str, Field(max_length=255)]]
    file_name: NotRequired[Annotated[str, Field(max_length=255)]]


class AttachmentSubmissionReader(Protocol):
    async def submit_attachment(self, file: AttachmentFile) -> dict: ...


def validate_attachment_file(file: object) -> AttachmentFile:
    """Validate without coercion or echo; URL trust is enforced by the fetching host."""
    limits = {"download_url": 8192, "file_id": 256, "mime_type": 255, "file_name": 255}
    if not isinstance(file, dict) or not {"download_url"} <= set(file) <= limits.keys():
        raise AnalysisError("invalid_input")
    for name, value in file.items():
        minimum = 1 if name in {"download_url", "file_id"} else 0
        if (
            not isinstance(value, str)
            or not minimum <= len(value) <= limits[name]
            or any(unicodedata.category(char).startswith("C") for char in value)
        ):
            raise AnalysisError("invalid_input")
    try:
        url = urlsplit(file["download_url"])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.fragment
            or url.port not in (None, 443)
            or "\\" in file["download_url"]
            or any(char.isspace() for char in file["download_url"])
        ):
            raise ValueError
    except ValueError:
        raise AnalysisError("invalid_input") from None
    if "file_name" in file and credential_filename_denied(file["file_name"]):
        raise AnalysisError("sensitive_file")
    return dict(file)
