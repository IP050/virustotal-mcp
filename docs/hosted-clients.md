# Hosted ChatGPT and Claude connections

The tested client guides remain [Agy](clients.md#antigravity-cli-agy),
[Claude Code](clients.md#claude-code), then [Codex](clients.md#codex-cli--remote-http).
This page covers separate hosted connections. The VirusTotal plugin is published
in ChatGPT. Its directory listing and the earlier connection checks below are
separate evidence.
The [validation scope](#validation-scope) records the verified ChatGPT connection,
IP reports and automatic renewal, earlier staging checks and remaining hosted workflows.

VTAI's public endpoint is `https://ai.virustotal.com/mcp`. It supports MCP OAuth
and also accepts a static VTAI Agent Token through one credential header,
including `Authorization: Bearer`. The service's ten common tools cover four report
lookups, file and URL submission, domain/IP reanalysis, and receipt and analysis
reads. Protected-resource and authorization-server metadata, DCR and CIMD are
live. The hosted backend advertises eleven tools, including `submit_attachment`
for an original file available through a public HTTPS URL. Discovery does not
establish that a client can provide an attachment's original bytes or URL. Local
stdio instead adds `submit_local_file`; remote HTTP cannot read local paths.
A successful CLI session does not establish another hosted account or workflow.

## File transfer depends on the host

For a file submission explicitly requested by the user, when the client can
supply the actual bytes, use `submit_file` with their SHA-256
and base64 content. Remote HTTP does not by itself prevent file transfer, and an
attachment in chat does not by itself prove that the host can access its bytes.

### Attachment downloads

Use `submit_attachment` only when the user explicitly requests submission of the
selected original file. It accepts one `file` object with a required public HTTPS
`download_url` string and optional `file_id`, `mime_type` and `file_name` strings.
Use a user-selected or host-provided download URL for the original bytes; never
invent a URL, paste credentials or substitute a local path. Metadata does not
establish permission to submit the file.

The optional fields retain compatibility with existing host file objects. The
`openai/fileParams: ["file"]` metadata is preserved for hosts that use that
[file-input extension](https://developers.openai.com/plugins/reference#define-file-inputs).
Other clients can supply the same neutral descriptor when they can provide a
reachable public HTTPS URL. This does not establish native attachment support in
Claude or any other specific host.

The backend downloads the original attachment with bounded time and
size (24,000,000 bytes), hashes its original bytes and uses the existing file
submission permission and receipt flow. A successful response supplies the
SHA256 for `get_submission`; use its registered analysis ID with `get_analysis`.
Never replay an uncertain upload. If interrupted before receiving its SHA256,
do not invent a receipt or retry to find out whether it was sent.

VTAI verifies the attachment's bytes and checks its hash before uploading. Only a
confirmed unknown file is uploaded, without consuming query quota. A known file
is not uploaded; returning its existing report consumes one query and is denied
when quota is exhausted. Owned receipt recovery costs no query, while report and
analysis reads count on every call. See [file workflow quota](analysis.md#query-quota-for-file-workflows).

An explicit user request, standard sharing and sensitive-content permission still
apply. A supplied
`file_name` is checked against the same short credential-name list as the Claude
plugin. It is optional, unverified metadata, not proof of the real filename or
file contents. Do not omit or rename it, encode bytes or change upload channels
to evade a denial.

This is a hosted-only capability; stdio does not expose the tool. If it is absent,
refresh the connection's tool inventory after the backend deployment. These
instructions and protocol tests do not establish native attachment transfer or
availability in every account.

### Existing web fallback

If the client cannot transmit those bytes, first calculate the file's SHA-256
locally, or ask the user for it, and call `get_file_report(hash)`. Use an existing
report without uploading. Only an explicitly requested submission and a confirmed missing report permit
offering the
existing [VirusTotal upload page](https://www.virustotal.com/gui/home/upload).
Permission, quota or service errors do not establish absence. Standard
uploads are not confidential and share content with the security community and
partners. Ask before sharing the user's own documents, internal code, credentials
or personal data, including sensitive content inside an attachment or unfamiliar
file. This alternative does not bypass host permissions or quota errors.

After the user uploads the confirmed unknown file through the website, use
`get_file_report(hash)` with the same hash. The report may not be available yet. Web uploads do not
create VTAI receipts or register analysis IDs: do not use `get_submission` or
`get_analysis` for that external upload. Every report query consumes
quota, including missing reports and cache hits; keep later reads within a finite
task budget. See [file transfer and recovery](analysis.md#when-the-client-cannot-transmit-file-bytes).

## Claude organization request-header beta

**Status: documented setup for eligible organizations; not tested in Claude.**
Anthropic restricts Request headers to selected organizations. If the field is
absent, this route is unavailable in that account. The organization deliberately
shares one VTAI identity, including its quotas and submission ownership; this
is suitable only when that shared access is intended. Individual identities
require the OAuth route below.

1. Obtain an organization-owned VTAI token using the [access guide](access.md).
   Keep a protected copy for revocation. Use neither another user's token nor a
   development/CI credential.
2. In the organization's custom-connector dialog, enter the endpoint above and
   choose **Authentication: None**. This selects the host's non-OAuth mode;
   VTAI still authenticates every request.
3. Under **Request headers**, add required **Authorization** with the complete
   value `Bearer ` followed by the token. Enter it only in that credential field.
   Do not add `x-apikey` or OAuth to this connection.
4. Enable the connector in a conversation and run the acceptance query below.
   If authentication settings need changing later, remove and recreate the
   connector; removing it alone does not revoke VTAI access.

These steps follow [Anthropic's request-header documentation](https://claude.com/docs/connectors/custom/remote-mcp#authenticating-with-request-headers).
Host permissions still govern tool execution. Configure them for the intended
operations; the server's submission tools do not add a per-call confirmation
argument. The host may request confirmation independently.

## ChatGPT public connection and individual OAuth

**Status: [VirusTotal is published in the ChatGPT plugin directory](https://chatgpt.com/plugins/plugin_asdk_app_6abadac2d9a08191ae2307c047bb3806).**
Browser consent, MCP IP reports and automatic token renewal were verified
separately in ChatGPT Work on 2026-09-24. Those checks did not cover revocation
from the hosted application, incremental authorization or writes. Publication
does not validate every workflow or native attachment transfer.

### Connect ChatGPT Work

1. Open the [VirusTotal plugin](https://chatgpt.com/plugins/plugin_asdk_app_6abadac2d9a08191ae2307c047bb3806)
   and select **Install plugin**. The published plugin does not require Developer
   mode. Installation and use depend on your account and workspace policies.
2. Connect VirusTotal when prompted. Continue with Google on VTAI, review the
   permissions and select **Allow access**. If needed, open the plugin's linked
   application and choose **Connect** under **Connected accounts**.
3. Start a **new chat**, type **@**, select **VirusTotal**, and ask:

   > Get the domain report for virustotal.com. Show the source, analysis date,
   > coverage and report link.

Confirm that the conversation contains the MCP tool result. An answer based on
browsing the public VirusTotal website does not establish that MCP was used.
If installation is unavailable, check your account and workspace policies. If
no login opens or no tools appear, check **Connected accounts** in the plugin's
linked application and choose **Connect** or **Connect another account** if
needed. Refresh the application's tools if that control is available, then start
a new chat. Keep a working account connection; an Agent Token is not needed for
OAuth. See OpenAI's [plugin guide](https://learn.chatgpt.com/docs/plugins).

### Alternative: create a custom app

Use this separate route for a custom setup. It requires an account and workspace
that permit **Developer mode**, enabled in ChatGPT settings.

1. In **Plugins**, create a plugin/application named **VirusTotal**, or reuse your
   existing custom application. Enter **`https://ai.virustotal.com/mcp`**, choose
   **OAuth**, and leave optional **Client ID** and **Client Secret** fields blank
   for automatic registration.
2. Create the application and install the custom plugin if prompted. Under
   **Connected accounts**, choose **Connect**, continue with Google, review the
   permissions and select **Allow access**.
3. Start a new chat and select your VirusTotal entry. Keep one working VirusTotal
   connection. Preserve existing access and any pending submissions when
   switching setups.

Do not enter an Agent Token or VirusTotal API key in OAuth client fields or chat.
See OpenAI's [custom connection guide](https://developers.openai.com/plugins/deploy/connect-chatgpt).

### OAuth compatibility

ChatGPT's authenticated public MCP connection uses OAuth. A static VTAI token
cannot be entered as an OAuth client secret. Its authorization contract includes
PKCE S256, protected-resource and issuer discovery, and resource-bound access
tokens. CIMD or a pre-registered client can avoid dynamic client registration.
[OpenAI authentication](https://developers.openai.com/plugins/build/auth).

VTAI uses a maintained authorization provider and validates issuer, resource,
expiry, approved scopes and active grants before applying its access controls,
quotas and receipt ownership. The resource is `https://ai.virustotal.com/mcp`,
and the issuer is `https://ai.virustotal.com`. Clients can discover these through
[protected-resource metadata](https://ai.virustotal.com/.well-known/oauth-protected-resource/mcp)
and [authorization-server metadata](https://ai.virustotal.com/.well-known/oauth-authorization-server).
The advertised registration endpoint supports DCR, and discovery advertises
Client ID Metadata Document (CIMD) support. Configure the MCP URL without static
headers for OAuth and follow the host's sign-in and consent flow. Support for
these protocols does not by itself establish compatibility with a hosted account.

**CIMD authentication negotiation:** ChatGPT's current client metadata offers
`none` and `private_key_jwt` in `token_endpoint_auth_methods_supported`, alongside
a legacy singular preference for `private_key_jwt`. VTAI OAuth **0.10.2 or later** can select `none` when a
CIMD document explicitly offers it, using mandatory PKCE S256. This does not add
JWT client authentication: a client requiring only `private_key_jwt` remains
unsupported. DCR continues to support `none`, `client_secret_basic` and
`client_secret_post`. Public-client negotiation does not change redirect checks,
resource binding, approved scopes or grant revocation.
Check the deployed version at [`/oauth/health`](https://ai.virustotal.com/oauth/health).
With an earlier server version, select DCR where the host offers it.
[OpenAI's negotiation rules](https://developers.openai.com/plugins/build/auth).
The ChatGPT consent, report and renewal checks below exercised a real hosted
connection. Protocol negotiation alone does not validate its remaining workflows.

For report and receipt reads, request `vt:reports:read`. File submission additionally
requires `vt:submissions:write`; URL submission and domain/IP reanalysis require
`vt:network-analysis:write` instead. Both write permissions require reports-read.
Existing connections do not gain the new network scope through token refresh:
reconnect and approve it when needed. Consent applies to the connection without
a VTAI confirmation on every operation; the host's tool permissions still apply.

Claude also supports OAuth for individual accounts. Use the exact callback and
registration mode documented for the chosen host; a client secret and DCR are
not universal requirements. [Claude authentication](https://claude.com/docs/connectors/building/authentication).

For private ChatGPT testing, OpenAI also offers Secure MCP Tunnel with stdio or
HTTP. It requires Platform tunnel permissions, a runtime API credential and the
correct ChatGPT workspace association. It does not replace the authenticated
public endpoint required for plugin distribution. No tunnel is provisioned or
validated by this project. [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

## Validation scope

The public [VirusTotal plugin listing](https://chatgpt.com/plugins/plugin_asdk_app_6abadac2d9a08191ae2307c047bb3806) provides the installation route. Directory publication is separate from the runtime checks below.

On 2026-09-24, a ChatGPT Work application completed personal browser consent
against production and returned an IP report through MCP. The same connection
later renewed its token automatically and returned another IP report after the
previous access token had expired, without another consent step. Report requests
linked to the same OAuth connection and refresh-state transitions corroborated
these operations. This verifies initial hosted authorization, report reads and
automatic renewal for that connection. It does not verify revocation from the
hosted application, incremental authorization, write workflows or the later published-plugin
installation route. The account connection was retained for continued use.

On 2026-09-14, a native Codex browser login and domain report succeeded in staging.
These were direct client calls, not model conversations or a hosted ChatGPT test.
On 2026-09-15, an owned Smithery hosted connection completed CIMD authorization
and consent, discovered the then-current seven tools and returned one domain
report in staging. The check used the documented Smithery Connect API alias with
a pinned CLI adaptation; it does not certify the unmodified CLI. A later call was
denied after grant revocation, but its access token had already expired, so that
observation does not prove immediate rejection of an unexpired token.

Those staged flows establish their stated operations, not a hosted production
login, every tool or a commercial-model workflow. They predate the new network
tools and permission. The later ChatGPT result above has its own limited scope;
Claude hosted chat workflows remain unverified. An existing claude.ai connection
was imported into Claude Code and used for MCP calls on 28 September 2026.
That observation does not establish a report conversation, renewal or uploads
inside Claude web chat or Desktop. Claude Code's later fresh plugin-owned OAuth
and tool checks on 1 October have their [own validation scope](claude-code.md#validation-and-removal).

## First hosted acceptance query

For an initial read-only check, enable only `get_domain_report` in the host's
tool permissions where available. In a new conversation, ask:

> Use VirusTotal to get the domain report for example.com. Explain the source,
> analysis date and coverage. Do not submit a file or start an analysis.

Accept the connection only after observing the actual tool call and its result,
not just a Connected label or an assistant's prose. Record the host/account
mode, discovered tools, call name, domain, outcome, report link, source,
analysis date, retrieval time and coverage. Exclude the credential and private
conversation content from evidence. Use the connection's discovered tool list;
the local-file tool is available only through stdio.

A missing report remains unknown; errors and incomplete coverage are not safety
verdicts. A passing query does not validate file or network submission, refresh, revocation,
other tools or publication in a host's directory. Test those as separate flows.
For temporary testing, remove the connector and revoke its access: use
[Your connections](https://ai.virustotal.com/oauth/connections) for OAuth, or the
[access guide](access.md#revoke-access) for a static Agent Token.

For OAuth acceptance, verify receipt isolation between identities, rejection of
expired or revoked access, and refresh preserving the same VTAI identity. A
submission test must use intentionally public inert bytes and recover its
original receipt without repeating an ambiguous upload. For an authorized network
operation, persist a lowercase UUIDv4 before dispatch and recover with
`get_submission(request_id=request_id)` through the same connection. Read
`get_analysis(analysis_id, request_id=request_id)` within a finite polling budget.
See [network analysis and recovery](analysis.md#network-analysis-and-recovery).
