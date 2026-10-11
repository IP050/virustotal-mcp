---
name: threat-intelligence
description: Investigate files, URLs, domains and IP addresses with VirusTotal. In Claude Code, submit local files through the bundled upload hook only when the user explicitly requests it.
---

Use the authenticated VirusTotal MCP connection. Prefer the already connected
imported VirusTotal connection or the server bundled with this plugin; avoid
creating duplicate connections. If authentication is missing, use `/mcp` in
Claude Code or connect VirusTotal from the plugin's Connectors tab in Claude
web chat. Never read or copy OAuth tokens.

Consult reports for the indicator and explain their source, date, coverage and
limitations. A missing report means unknown; zero detections do not prove safety.
Every report query, including a repeat or a missing report, counts toward quota.

Submit files or request URL, domain or IP analyses only when the user explicitly
requests that action. A missing report or unfamiliar file is not permission to submit.
Ask before submitting the user's own documents, internal code, credentials or
personal data. Being an attachment or having an executable extension does not
establish permission to share private content. Standard submissions are shared
with the VirusTotal community and security partners; submit only material you
have the right and permission to share.

The local `file:` workflow below requires Claude Code and the bundled hook.
Claude web chat does not run this hook and cannot read a path on the user's
computer. Do not claim that a local path has been uploaded from web chat.

For a local file submission explicitly requested by the user in Claude Code:

1. Calculate SHA256 from the original file with an available local tool, within
   the user's authorized file scope. Do not execute the file. A previous MD5 or
   SHA1 lookup does not supply its SHA256.
2. Call this connection's `submit_file` with that lowercase SHA256 and
   `content_base64: "file:<absolute local path>"`. Do not transcribe base64. The
   plugin validates the original bytes and expands this local reference before
   the remote call. Paths must be under the current working directory or an
   explicitly configured `VTAI_UPLOAD_ROOTS` directory. The hook allows a valid
   expansion automatically; it does not decide whether sensitive content may be
   shared.
   If the hook blocks a possible credential filename, stop and ask the user for
   human review. Do not rename, encode, switch tools or use the web uploader to
   bypass that block; there is no automatic override.
3. The server verifies the original bytes and checks their hash first. Only a
   confirmed missing report permits an upload. A known file returns its existing
   report without uploading again. New contributions consume no report-query
   quota; existing reports and explicit queries remain charged.
4. Retain the SHA256 and receipt when one is returned. If a submission is uncertain, use
   `get_submission` with the same SHA256; never replay the upload to check it.
   When an analysis ID is available, respect `next_poll_after_seconds` before
   `get_analysis`. Pending results are not completed analyses.

Use `submit_url` only when the user explicitly requests URL analysis. Retain its
request ID and use the receipt tools exposed by that connection to recover an uncertain outcome.
Do not switch connections, credentials or services to evade a permission or
quota rejection. Honor retry delays.

The `file:` convention requires this local hook. If it is unavailable and the
host cannot transmit the original bytes, obtain the actual file hash and call
`get_file_report` first. Use an existing report without uploading. Only an
explicitly requested submission and a confirmed missing report permit offering
the existing
https://www.virustotal.com/gui/home/upload interface, then querying the same
hash again. Permission, quota and service errors do not establish absence.
A web upload does not create a VTAI submission receipt.
