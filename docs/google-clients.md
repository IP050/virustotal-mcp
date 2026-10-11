# Google client connections

Start with [Agy](clients.md#antigravity-cli-agy); the other primary guides are
[Claude Code](clients.md#claude-code) and [Codex](clients.md#codex-cli--remote-http).
This page covers [Gemini Apps](#gemini-apps-custom-connection), its optional
[importable skill](#gemini-apps-skill), the Antigravity plugin, native remote
configuration, [Gemini API managed agents](#gemini-api-antigravity-managed-agent)
and the Gemini CLI extension. The existing Agy stdio setup remains
available for unattended use. [VT Sentinel for Antigravity IDE](https://open-vsx.org/extension/virustotal/vt-sentinel)
is a separate editor extension, also linked from [ai.virustotal.com](https://ai.virustotal.com/).

## Gemini Apps custom connection

Google currently requires a personal account, age 18 or older, US availability,
English and **Keep Activity** enabled for custom connected apps. Set up the
connection in the web app; it can then be used on web and mobile. Work and school
accounts are not eligible for this flow. Check
[Google's current custom-app requirements](https://support.google.com/gemini/answer/17209137?hl=en).

1. Open [Gemini](https://gemini.google.com/) and choose **Settings → Connected Apps**.
2. Under **Custom apps**, add `https://ai.virustotal.com/mcp`, then continue with **Next**.
3. Complete the browser sign-in and VTAI consent. VTAI supports dynamic client
   registration; this recipe needs no manually entered client ID, client secret,
   static Agent Token or premium VirusTotal API key. Authorize only the operations
   your task needs, and keep credentials out of the conversation.
4. In a chat, type `@` and select the connected VirusTotal app. Request an existing
   report, for example:

   > Retrieve the existing VirusTotal report for example.com. Include the source,
   > analysis date, coverage and report link. Do not submit it or request a new analysis.

Check the actual tool result before relying on the answer. An account connection
alone does not establish a successful report query. Missing reports mean unknown;
zero detections do not prove safety. This is a custom connection, not a claim of
placement in Gemini's curated app directory.

If **Custom apps** is absent, check eligibility and availability. Google currently
limits this connection flow to the US; seeing **Skills** in another country does
not establish custom-app access. Installing the skill does not enable this
connection. For a login failure, use the client's reconnect
flow and your existing VTAI account. The Gemini model account and the VTAI
connection are separate. VTAI access has its own quotas; Gemini plan requirements
and model limits are controlled by Google.

### Sharing and permissions

Only disclose indicators you may share. URL lookups send the complete URL,
including query and fragment, to VTAI and VirusTotal; prefer a domain lookup when
private paths are unnecessary. Review [VTAI's connection information](https://ai.virustotal.com/connect/mcp)
and the [privacy notice](https://cloud.google.com/terms/secops/privacy-notice).

Report lookups retrieve existing intelligence. File submissions, URL analysis and
domain/IP reanalysis use separate write tools and permissions. Standard
submissions require the user's explicit request and are shared with the VirusTotal
community and security partners. Ask
before sharing the user's own or sensitive content, and respect host confirmation
and permission controls. The remote service cannot read a device path. An attachment in chat does not establish that the host
can supply its original bytes or a reachable public HTTPS download URL. A model
must not invent attachment URLs, hashes or base64. See [submission and recovery](analysis.md) for supported
byte transfer and the hash-first web-upload alternative.

Every explicit report or analysis read consumes query quota, including repeats,
cache hits and missing reports. New-file contributions and owned receipt recovery
have the [separate accounting described here](analysis.md#query-quota-for-file-workflows).
Honor retry delays; a timeout or quota refusal is not a clean result or permission
to resubmit. Keep an uncertain operation's receipt or request ID and recover it
using the same connection.

### Remove access

In Gemini's **Connected Apps**, turn the custom app off to stop using it. Use
**More details → Disconnect** to unlink it, or **Remove app** to remove it.
For permanent removal, also verify or revoke the grant in VTAI's
[Your connections](https://ai.virustotal.com/oauth/connections). Deleting a skill
does not revoke its MCP connection or withdraw previously submitted content.

## Gemini Apps skill

The portable [VirusTotal threat-intelligence skill](../skills/virustotal-threat-intelligence/README.md)
adds investigation and sharing instructions. You can import its instructions
independently, but live VirusTotal queries require the MCP app above to be
connected. Importing a skill does not install a server, authenticate it or grant
access.

Skills require a personal Google account, age 18 or older and **Keep Activity**.
Availability is gradual and does not itself require a paid subscription. These
skill requirements are distinct from the US/English restrictions on custom apps.
See [Google's skill import guide](https://support.google.com/gemini/answer/17094296?hl=en).

1. Download the plain-text [SKILL.md](https://github.com/VirusTotal/virustotal-mcp/releases/download/gemini-skill-v0.1.0/SKILL.md)
   and review its instructions. Keep the filename `SKILL.md`.
2. On Gemini web, open **Settings → Skills → Upload**, select `SKILL.md`, then
   review it and choose **Create**. Some upload dialogs accept only this file;
   use it directly when the dialog rejects a ZIP.
3. In a chat, type `/` to select `virustotal-threat-intelligence`. If you have
   connected the VirusTotal app, use `@` to select it and try the report-only
   prompt above. Without that connection, the skill cannot retrieve live reports.

The [release](https://github.com/VirusTotal/virustotal-mcp/releases/tag/gemini-skill-v0.1.0)
also provides a ZIP and checksums. If you downloaded the ZIP, extract its single
`SKILL.md` and select that file. Google's guide describes ZIP and folder imports,
but available upload formats can differ between interfaces.

The skill contains instructions only, with no scripts, credentials or network
helpers. Google does not support internet-accessing scripts in imported skills;
the connected app supplies the MCP tools. Hosts may expose different tools:
the skill uses only the available connected tools and their current schemas.

To update an import, review the new file and use **Replace skill** in its menu.
You can deactivate or delete it from **Settings → Skills** independently of the
MCP connection. Existing imports do not change when this repository changes.

## Antigravity plugin

The [VirusTotal plugin](../plugins/antigravity/README.md) bundles the remote OAuth
MCP configuration and a threat-intelligence skill. Install its local directory
from the official source repository:

```sh
git clone https://github.com/VirusTotal/virustotal-mcp.git
agy plugin validate ./virustotal-mcp/plugins/antigravity
agy plugin install ./virustotal-mcp/plugins/antigravity
agy plugin list
```

Agy 1.2.14 expects a local directory for this source installation. Use the plugin
subdirectory, not the repository root or a GitHub subdirectory URL. In the
interactive `/plugin` manager, choose **Install from local directory**.
[Google's plugin installation guide](https://antigravity.google/docs/plugins/).

If you already have a working `virustotal` connection, choose one active
connection and preserve unrelated configuration. Recover uncertain submissions
before switching identities. Existing stdio and VT Sentinel installations remain
available; this plugin does not add an execution interception or local upload
hook. Its remote MCP server cannot read a local file path.

Follow the authentication steps below, then request an existing report such as
example.com without submitting it for analysis. See the plugin's
[permissions, sharing, costs and removal instructions](../plugins/antigravity/README.md).
An installed plugin is not evidence of a successful OAuth flow or a Marketplace
listing.

## Antigravity native OAuth

If you installed the plugin above, authenticate its existing
`virustotal_virustotal` server in `/mcp`; skip the manual configuration below.

Merge [antigravity-oauth.json](../examples/client-configs/antigravity-oauth.json)
into the configuration opened by your application's MCP manager:

```json
{
  "mcpServers": {
    "virustotal": {
      "serverUrl": "https://ai.virustotal.com/mcp"
    }
  }
}
```

Preserve other servers. Replace an existing `virustotal` entry rather than mixing
`command` and `serverUrl` or configuring two connections. This OAuth recipe has no
static token, custom header or Google ADC requirement. Antigravity's remote field
is `serverUrl`; Gemini CLI's `httpUrl` is a different configuration format.

For Agy, the equivalent command is:

```sh
agy mcp add --type http virustotal https://ai.virustotal.com/mcp
```

Reload the server in `/mcp`, select it and choose **Authenticate**. Complete the
browser consent and copy the callback page's code into the authentication dialog,
not the conversation. Antigravity's graphical MCP settings also provide an
**Authenticate** action. Approve only permissions needed for your tasks. An
Antigravity model login does not itself grant VTAI access.

If your installed client has no working OAuth action, use the
[stdio token-file setup](clients.md#antigravity-cli-agy). Do not work around a
missing OAuth flow by pasting a credential into a shared JSON file.

Google documents global configuration at `~/.gemini/config/mcp_config.json` and
workspace configuration at `.agents/mcp_config.json`. Use the application's
**View raw config** action to select the right file for your version.
[Official configuration and OAuth guide](https://antigravity.google/docs/mcp).

For updates, refresh/reconnect the remote server; no local vt-mcp package is used.
Remove it through the manager or `agy mcp remove virustotal`. Also revoke the
connection in [Your connections](https://ai.virustotal.com/oauth/connections) when
disconnecting permanently; removing a local entry alone does not revoke access.

## Gemini API: Antigravity managed agent

Developers can connect Google's managed `antigravity-preview-09-2026` agent to
the remote MCP service. This runs through the Gemini API, separately from Agy,
the Antigravity IDE and Gemini Apps. You need Gemini API access to this preview
agent and a [VTAI credential](access.md) with report access. The verified setup
used an OAuth access token with only `vt:reports:read`.

For `POST https://generativelanguage.googleapis.com/v1beta/interactions`, send
`Content-Type: application/json` and `Api-Revision: 2026-05-20`. Your application
reads `GEMINI_API_KEY` from its protected environment for Google's
`x-goog-api-key` header. Construct the request body in memory:

| Field | Value |
|---|---|
| `agent` | `antigravity-preview-09-2026` |
| `environment` | `remote` — a fresh Google sandbox, with no mounted sources or reused environment |
| `background`, `store` | Both `true` |
| `input` | Ask for exactly one existing `get_domain_report` for `example.com`, then a brief summary with source, dates and the limit that unknown does not mean safe |
| `tools` | Array containing one object: `type: "mcp_server"`, `name: "virustotal"`, `url: "https://ai.virustotal.com/mcp"` |
| `tools[0].allowed_tools` | `[{"tools":["get_domain_report"]}]` |
| `tools[0].headers.Authorization` | `Bearer ` plus the VTAI access token read from a protected `VTAI_MCP_TOKEN` environment variable |

Resolve credential environment variables in your application before constructing
headers. Keep both credentials out of prompts, command arguments and logs.
Your application manages OAuth consent and token lifetime; an inline MCP bearer
does not provide automatic renewal during a managed run.
[Google's agent guide](https://ai.google.dev/gemini-api/docs/antigravity-agent)
and [Interactions schema](https://ai.google.dev/api/interactions-api) describe
this contract. The explicit tool list excludes search, URL context and code
execution; Google automatically enables sandbox filesystem tools when an
environment is present. No local files or repositories are supplied here.

Save the returned interaction ID before polling its GET endpoint. Verify the
actual MCP call and matching report result, not only the generated answer.
Bound the polling period; cancel a still-running interaction with
`POST /v1beta/interactions/{id}/cancel`. An accepted create followed by an error
does not justify another create. At completion, delete the exact returned
environment with `DELETE /v1beta/environments/{environment_id}` and verify its
absence. Google documents automatic stop after 15 minutes idle and deletion
after seven days of retention; see [environment lifecycle and cleanup](https://ai.google.dev/gemini-api/docs/agent-environment#environment-lifecycle).
Revoke temporary VTAI grants after use. Google's billing is independent of VTAI
access and query quotas. Check [Gemini API pricing](https://ai.google.dev/gemini-api/docs/pricing).

## Gemini CLI extension

Gemini CLI users with an eligible model account can install the extension from
the official source repository:

```sh
gemini extensions install https://github.com/VirusTotal/virustotal-mcp --ref main
gemini extensions list
```

Accept the CLI's source-trust prompt after reviewing the repository. `--ref main`
selects the current manifest; older package release archives do not contain it.
If the CLI offers a Git-clone fallback for that branch, accept it. Git is required.
There is no Python process, package installation or token-setting prompt in this
extension: it connects to the hosted service using OAuth.

Extension version **0.9.9** includes the portable
[`virustotal-threat-intelligence` skill](../skills/virustotal-threat-intelligence/README.md).
Gemini CLI discovers it from the extension's `skills/` directory. Its instructions
use the existing connection and do not change OAuth scopes or tool permissions.
The version identifies this source distribution; it does not upgrade a local
Python installation or identify the deployed VTAI backend version.

If `virustotal` already exists in your Gemini `settings.json`, choose one
connection and preserve unrelated entries. A manual entry can override the
extension's server; installing the extension does not migrate existing settings.

Start Gemini in a trusted workspace and run:

```text
/mcp auth virustotal
/mcp list
```

Complete browser sign-in and consent. The extension requests report access, file
submission and network-analysis permissions. Submission permissions allow your
application to send authorized files or indicators under VirusTotal's standard
sharing terms without a VTAI confirmation on each call. Host tool permissions
still apply. For a read-only manual setup, copy the manifest's `mcpServers` entry
into your own configuration with only `vt:reports:read` in `oauth.scopes`, and
disable the extension to avoid duplicate configuration. Adding write scopes later
requires a new consent; refreshing an old token does not expand its grant.

Run an actual report query to verify the connection:

> Use VirusTotal to retrieve the existing report for example.com. Explain its
> source, analysis date and coverage. Do not request a new analysis.

Inspect the tool result. A connected status or successful install alone does not
establish that a model called a tool. The hosted service advertises eleven tools:
ten common report, submission and recovery tools, plus `submit_attachment`.
That tool requires a public HTTPS URL for the original file; its presence does
not establish native Gemini attachment transfer. Local stdio instead adds
`submit_local_file` to the ten common tools.

Maintain or remove the extension with:

```sh
gemini extensions update virustotal
gemini extensions uninstall virustotal
```

Restart Gemini after an update. Uninstalling does not revoke the grant; use
[Your connections](https://ai.virustotal.com/oauth/connections). Reuse your existing
access after quota errors rather than registering another identity.

Google retired consumer Gemini CLI Google login for Code Assist individuals,
Google AI Pro and Ultra on 18 June 2026. Those users should use Agy. Eligible
Standard/Enterprise accounts and Gemini API-key authentication have separate
model-access requirements; installing this extension does not provide model
access. [Google transition notice](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/).

## Validation and discovery

The Gemini Apps setup and skill import instructions follow Google's documentation
checked on 3 October 2026 and an upload dialog that accepts only `SKILL.md`.
The plain-text download is identical to the file in the skill release ZIP;
its format and archive contents were checked locally. A manual upload on that
date showed `virustotal-threat-intelligence` under **Active** in Gemini web.
This verifies import and listing, independently of the MCP connection.
A complete Gemini Apps MCP login, imported-skill report query,
token renewal and write workflow have not been exercised in this validation.
Historical server-side OAuth activity does not establish that end-to-end workflow.
Do not infer Gemini Apps support from the separate Agy check below.

On 2 October 2026, Gemini CLI 0.58.0 installed extension 0.9.8 from this public
repository, discovered the portable skill and uninstalled the extension in an
isolated client configuration. A separate read-only skill-loader check verified
its format. These checks do not establish OAuth or a model-driven report query.

In a separate session on that date, Gemini CLI 0.58.0 used Gemini API-key model
authentication with `gemini-3.5-flash` and a separately supplied VTAI OAuth
access token in a Bearer header. It completed one remote `get_domain_report`
call for example.com, received a matching `found` report and recorded no error
events. The temporary grant was revoked and the isolated client profile removed.
Extensions and skills were disabled during this query. Native CLI OAuth login
and automatic token renewal remain unverified.

On 2 October 2026, Gemini API's `antigravity-preview-09-2026` completed one
`get_domain_report` call for example.com over remote MCP and returned a matching
`found` report. The interaction recorded no other tool steps, and the temporary
VTAI OAuth grant was revoked with confirmation. The run's sandbox was deleted
and a subsequent GET confirmed its absence. This validates one domain lookup;
other reports, writes and automatic token renewal were not exercised.

Deep Research remains unverified: `deep-research-preview-04-2026` accepted an
interaction, then its status reads returned a Google processing error. A domain
query reached VTAI, but Google's tool steps and report output could not be
recovered. This does not establish MCP incompatibility or a completed workflow.

On 2 October 2026, Agy 1.2.14 validated and installed the Antigravity plugin.
The manifest contains only the documented `name` and `description` fields; its
remote connection uses `serverUrl`. The native OAuth flow completed browser
sign-in, explicit consent, Google's callback page and code entry in Agy's own
authentication dialog. A fresh Agy 1.2.15 session then used that connection for
one `get_domain_report` lookup of example.com, returning an existing report with
source, analysis date, coverage and a VirusTotal link. The client updated between
sessions; the installed MCP configuration and skill were unchanged. The lookup
used a one-call permission, without changing persistent tool permissions.

The temporary grant was then revoked; a fresh initialization was rejected and
the client no longer had the report tool. This verifies the plugin's initial
OAuth, report and revocation workflow in the CLI. The manual `serverUrl` entry
was not tested as a separate connection.
Automatic token renewal, file submissions, network reanalysis and the graphical
applications have not been exercised with this plugin. Marketplace acceptance
is a separate review process.

On 23 September 2026, Gemini CLI 0.58.0 installed the exact extension manifest
from a local checkout in an isolated client configuration. Its native extension
listing recognized version 0.9.1 and the `virustotal` MCP server. No production
OAuth consent, tool call or model workflow was performed in that check. The
manifest follows [Gemini's extension format](https://geminicli.com/docs/extensions/reference/)
and [MCP OAuth configuration](https://geminicli.com/docs/tools/mcp-server/).

Antigravity's OAuth fragment follows Google's current documentation. Agy 1.2.2
help accepts the HTTP add command; its `mcp list` command did not list a temporary
workspace-only fixture. Global configuration was preserved. These older
configuration checks are separate from the plugin workflow above; the earlier
[stdio workflow evidence](clients.md#validation-levels) retains its original scope.

The public repository's root `gemini-extension.json` provides gallery metadata.
Google's [gallery discovery process](https://geminicli.com/docs/extensions/releasing/)
uses the `gemini-cli-extension` repository topic and a periodic crawl. A published
manifest or topic is not proof of gallery acceptance or Antigravity Store placement.
On 2 October 2026, the public [gallery feed](https://geminicli.com/extensions.json)
listed `VirusTotal/virustotal-mcp` at version 0.9.8. This confirms that listing,
not Antigravity Store acceptance or usage.
