# Additional remote MCP clients

These configuration recipes connect to **`https://ai.virustotal.com/mcp`**.
They follow the linked client documentation; authenticated VirusTotal workflows
in these clients have not been verified for this guide. Configuring a connector
does not establish a successful tool call or a public directory listing.

| Client | Route | Validation level |
| --- | --- | --- |
| [Qwen Code](#qwen-code) | HTTP MCP with browser OAuth | Documented configuration |
| [Mistral Vibe Work](#mistral-vibe-work) | Custom MCP connector with OAuth | Documented configuration |
| [Grok web](#grok-web) | Custom MCP connector with OAuth | Documented configuration |
| [xAI Responses API](#xai-responses-api) | Remote MCP with a VTAI Agent Token | Documented API example |

VTAI authentication is separate from access to the client's model. OAuth uses
your VTAI account and its quota; no VirusTotal API key or local Python server is
required. Review the permissions requested by the client and approve the
connection only if they fit your intended use. The VTAI consent screen approves
or cancels the requested set; it does not offer individual scope checkboxes.

## Qwen Code

With [Qwen Code installed](https://qwenlm.github.io/qwen-code-docs/en/users/quickstart/),
run these POSIX shell commands. Reuse an existing `virustotal` entry if present.

```sh
export QWEN_CODE_FORCE_ENCRYPTED_FILE_STORAGE=true
qwen mcp add --scope user --transport http virustotal https://ai.virustotal.com/mcp \
  --include-tools get_file_report get_url_report get_domain_report get_ip_report
qwen
```

Open `/mcp`, select `virustotal` and complete browser authentication. Restart an
already running session after changing its configuration. The command exposes
only the four report tools to Qwen. It preserves normal host tool approvals;
tool filtering does not reduce the OAuth permissions granted to the connection.
[Qwen's MCP guide](https://qwenlm.github.io/qwen-code-docs/en/users/features/mcp/)
documents these commands, OAuth and `includeTools`.

Keep the encryption setting enabled whenever you launch Qwen. Its documented
default stores OAuth credentials in plaintext with mode `0600`; the setting
selects keychain storage where available or an encrypted file. See
[Qwen's credential-storage documentation](https://github.com/QwenLM/qwen-code/blob/main/docs/users/features/mcp.md#token-management).

The default browser callback is local to the machine running Qwen. For SSH or a
cloud terminal, follow Qwen's redirect configuration before signing in. This
recipe adds MCP directly and does not install the Claude Code plugin or its
local file-upload hook.

## Mistral Vibe Work

In Mistral Vibe Work, formerly Le Chat, an administrator can add a custom
connector. The account owner is the administrator on Free, Pro and Student plans.

1. Open **Connectors → + Add Connector → Custom MCP Connector**.
2. Set the connector name to `virustotal` and Server URL to
   `https://ai.virustotal.com/mcp`.
3. Choose **Connect** and complete VTAI sign-in and consent. Mistral documents
   automatic authentication detection, including OAuth with dynamic client
   registration.
4. In **My Connectors → virustotal → Functions**, review the per-tool permission
   settings. Keep submission and reanalysis tools subject to approval.

These steps follow [Mistral's MCP connector guide](https://docs.mistral.ai/vibe/work/connectors/mcp-connectors).
The custom connection is separate from Mistral's curated connector directory.

## Grok web

1. Open [Grok's connectors page](https://grok.com/connectors).
2. Select **New Connector → Custom** and enter
   `https://ai.virustotal.com/mcp`.
3. Complete VTAI browser sign-in and review the requested permissions.

This follows [Grok's custom MCP connector instructions](https://docs.x.ai/grok/connectors).
On Business and Enterprise, a team administrator first provisions the server in
**Grok Business → Connectors → + Add Connector → Other** in the xAI console;
members then connect their own accounts. See
[team connector management](https://docs.x.ai/grok/connector-management).

These are instructions for a custom connection in Grok web. The Grok Build CLI
has a separate plugin and authentication workflow. Availability in a particular
account and a complete VirusTotal workflow remain to be verified.

## xAI Responses API

Use this example in an application that already has xAI API access. Load
`XAI_API_KEY` and your existing `VTAI_AGENT_TOKEN` into its environment outside
chat, following the [VTAI access guide](access.md#remote-client-environment).
Set `XAI_MODEL` to an MCP-capable model available to your xAI account; consult
[xAI's model documentation](https://docs.x.ai/developers/models).
The two credentials serve different services. Keep them out of source control,
prompts, command arguments and request logs.

This Python standard-library example sends one Responses request and allows only
`get_domain_report`:

```python
import json
import os
from urllib.request import Request, urlopen

payload = {
    "model": os.environ["XAI_MODEL"],
    "input": [
        {
            "role": "user",
            "content": (
                "Use VirusTotal get_domain_report once for example.com. "
                "Explain its source, analysis date, coverage and report link. "
                "Do not request a new analysis."
            ),
        }
    ],
    "tools": [
        {
            "type": "mcp",
            "server_label": "virustotal",
            "server_url": "https://ai.virustotal.com/mcp",
            "allowed_tools": ["get_domain_report"],
            "headers": {
                "Authorization": "Bearer " + os.environ["VTAI_AGENT_TOKEN"],
            },
        }
    ],
}
request = Request(
    "https://api.x.ai/v1/responses",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + os.environ["XAI_API_KEY"],
    },
    method="POST",
)
with urlopen(request, timeout=120) as result:
    response = json.load(result)

for item in response.get("output", []):
    if item.get("type") == "mcp_call":
        print(json.dumps(item, indent=2))
    elif item.get("type") == "message":
        for part in item.get("content", []):
            if part.get("type") == "output_text":
                print(part["text"])
```

The request shape and `headers`/`allowed_tools` fields follow
[xAI's remote MCP documentation](https://docs.x.ai/developers/tools/remote-mcp).
That API does not support `require_approval`; do not rely on it for per-call
confirmation. This example exposes no submission or reanalysis tools.
The output inspection follows xAI's
[tool-call response types](https://docs.x.ai/developers/tools/tool-usage-details).
Your application manages credential lifetime; supplying a bearer token does not
perform browser OAuth or arrange token renewal. xAI model usage and VTAI query
quotas are separate.

## Verify and maintain the connection

For an interactive client, request:

> Use VirusTotal to retrieve the existing report for example.com. Explain its
> source, analysis date, coverage and report link. Do not request a new analysis.

Inspect the actual `get_domain_report` call and its matching tool result. A
connected indicator or an answer based on web browsing does not establish an
MCP report lookup. A missing report is unknown; zero detections do not establish
safety. Report lookups never authorize uploads or reanalysis. Those actions
require an explicit user request and the
[VirusTotal sharing guidance](../README.md#tools).

Remote HTTP cannot read local paths. Native attachment transfer is not established
by these recipes; see [hosted file transfer](hosted-clients.md#file-transfer-depends-on-the-host).
Honor retry intervals and retain your existing credentials after quota errors.

To stop OAuth access, revoke the relevant grant in
[Your connections](https://ai.virustotal.com/oauth/connections) and remove the
client's connector. For Qwen, remove the entry with
`qwen mcp remove --scope user virustotal`. Verify the VTAI grant directly rather
than assuming that deleting client configuration revokes it. Agent Tokens have a
separate [revocation procedure](access.md#revoke-access).

The examples' formatting and syntax can be checked locally. Native installation,
OAuth consent, report calls, renewal and revocation are separate acceptance
checks; this guide does not claim those workflows were completed for the clients
above. See the [client validation levels](clients.md#validation-levels).
