# Runbook — Mission 01: Getting eyes on the perimeter

How I connected my lab workstation to my own Microsoft Sentinel, in the order I did it, including what broke and how I fixed it. Someone else should be able to rebuild the same setup from this page.

## My setup at a glance

| Item | Value |
|---|---|
| Tenant / subscription | BECODE (becode.education) / *Azure for Students* |
| Region (used everywhere) | **Norway East** |
| Resource group | `rg-sentinel-lab` |
| Log Analytics workspace | `log-sentinel-lab-1` — Pay-as-you-go (Per GB 2018), 30-day retention |
| SIEM | Microsoft Sentinel enabled on `log-sentinel-lab-1` |
| Daily cap | **0.2 GB/day** |
| Workstation | `WKS-L51` (`WKS-L51.hamilton.corp`), Windows 10 Pro 22H2 (10.0.19045) |
| Arc agent | Connected Machine agent 1.68, status **Connected** |
| Log agent | `AzureMonitorWindowsAgent` 1.45 (Arc extension), status **Succeeded** |
| Chain A | `dcr-windowsevents` → table `Event` (Application + System only) |
| Chain B | `dcr-securityevents` → table `SecurityEvent` (Security log, *Common* set) |

Naming follows the Microsoft CAF convention: **type prefix + purpose** (`rg-`, `log-`, `dcr-`).

---

## Step 0–1 — Reach the workstation

1. Signed in to **Tailscale** on my laptop and waited for the coach to approve the device.
2. `ping <workstation address>` → replies. *(Do not open RDP before the ping answers: a timeout there is a network problem, not a machine problem.)*
3. RDP to the workstation with the account from my access sheet → forced password change on first logon → Windows desktop.

## Step 2 — Build the SIEM

### 2.0 Azure for Students
Portal (`portal.azure.com`) with my **BeCode school account** → search **Education** → **Sign up now** → **Start free** → country **Belgium**, address BeCentral (Cantersteen 15, 1000 Brussels).
Check: top-right of the portal shows **BECODE (BECODE.EDUCATION)**; *Education → Overview* shows 100 USD / 365 days.

### 2.1 Choose the region
Portal → **Policy → Assignments → "Allowed resource deployment regions"** → read my allowed list.

> **What broke:** I first tried a region that is *not* on my list and got **`RequestDisallowedByAzure`** with a message about policy/location on *Create*.
> **Fix:** chose **Norway East** from my allowed list and used it for **every** resource afterwards. Lesson: read the policy list *before* creating anything — the "usual" regions (West Europe, France Central) are often not allowed for student subscriptions.

### 2.2 Resource group, workspace, Sentinel
1. **Resource groups → + Create** → `rg-sentinel-lab`, Norway East.
2. **Log Analytics workspaces → + Create** → RG `rg-sentinel-lab`, Norway East, tier **Pay-as-you-go (Per GB 2018)** (the tier the Sentinel free trial applies to).

   > **What broke:** the name `log-sentinel-lab` was **already taken** and the portal refused it.
   > **Fix:** named it **`log-sentinel-lab-1`**. Everything else references this name. (A deleted workspace can keep its name reserved for a while — worth knowing if you recreate one.)

3. **Microsoft Sentinel → + Create** → select `log-sentinel-lab-1` → **Add**. The free-trial screen (31 days, 10 GB/day) appears — that is normal.

### 2.3 Daily cap
Workspace → **Settings → Usage and estimated costs → Daily cap** → **On**, **0.2 GB/day**.
Why 0.2: a quiet workstation sends far less, so the cap is a safety net against a runaway source, not a daily limit I expect to hit. Trade-off: if the cap is reached, collection stops until the next reset and I am blind.
Verified in the workspace JSON: `workspaceCapping.dailyQuotaGb = 0.2`.

## Step 3 — Connect the workstation

### 3.1 Azure Arc (make the machine known to Azure)
Portal → **Azure Arc → Machines → Onboard/Create → Onboard existing machines**:

| Field | Value |
|---|---|
| Subscription / RG | Azure for Students / `rg-sentinel-lab` |
| Region | Norway East |
| OS | Windows |
| Connect SQL Server | **unchecked** (machine now carries tag `ArcSQLServerExtensionDeployment : Disabled`) |
| Connectivity | Public endpoint, no proxy, no Arc gateway |
| Authentication | Authenticate machines manually |
| Management (preview) | nothing enabled |

On the workstation: **PowerShell → Run as administrator**, then first:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```
then paste the downloaded Arc script.

> **What broke:** the agent installed, but registration failed with **`RequestDisallowedByAzure` / `401` — "…without authenticating through MFA"**. The browser that opens *inside the VM* never prompts for MFA, so the token it gives the agent is refused.
> **Fix:** in the **same** admin window (the script leaves its variables in it) I re-ran the connect step with a device code:
> ```powershell
> & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --resource-group "$env:RESOURCE_GROUP" --tenant-id "$env:TENANT_ID" --location "$env:LOCATION" --subscription-id "$env:SUBSCRIPTION_ID" --cloud "$env:CLOUD" --tags 'ArcSQLServerExtensionDeployment=Disabled' --use-device-code
> ```
> and entered the code at `https://login.microsoft.com/device` **on my laptop**, in the browser already signed in to the portal (with MFA). Result: *Machine connected to Azure*.

Check: **Azure Arc → Machines → `WKS-L51`** = **Connected**.

### 3.2 Chain A — Data Collection Rule from Azure Monitor
Portal → **Monitor → Settings → Data Collection Rules → + Create** (from Monitor, *not* from Sentinel):

| Field | Value |
|---|---|
| Name | `dcr-windowsevents` |
| RG / Region | `rg-sentinel-lab` / Norway East |
| Telemetry type | Agent-based – Windows or Linux |
| Data Collection Endpoint / Managed identity | empty / unchecked |
| Resources | `WKS-L51` (Machine – Azure Arc) only |
| Data source | Windows Event Logs — Application: Critical, Error, Warning · System: Critical, Error, Warning · Security: Audit success + Audit failure *(Security removed later, see 5b)* |
| Destination | Log Analytics → `log-sentinel-lab-1` (table **`Event`**) |

Attaching the rule to the Arc machine is what installs the agent: after a few minutes **Arc → WKS-L51 → Extensions** showed **AzureMonitorWindowsAgent → Succeeded**.
*(Do not download `AzureMonitorAgentClientSetup.msi` — that is a dead end for this setup.)*

## Step 4 — Prove it is alive

**Sentinel → Logs**, switch the editor from *Simple mode* to **KQL mode**:
```kql
Heartbeat | take 10
```
Rows with `WKS-L51.hamilton.corp` appeared. Rule I keep: **check `Heartbeat` first** — no heartbeat = connection problem; heartbeat present = connection is fine, look elsewhere. Never judge the agent from the machine (`Get-Service AzureMonitorAgent` returns nothing on an Arc machine).

## Step 5 — First questions (see `queries.kql`)

What my data showed on 2026-10-08:
- **Last heartbeat** 18:42 UTC, two minutes before I checked → the machine is talking *now*.
- **Ingestion delay** normally **50–60 s** → clock is fine, pipeline is healthy.
- One heartbeat generated **2026-10-07 23:11 UTC** was only ingested at **2026-10-08 08:47 UTC** (≈ 9 h 35 min late). The workstation shut down at 23:11 (event 4647 logoff, 1100 log service shutdown) and booted again at 08:42 (event 4608). The agent sent its queued data on restart. **The `TimeGenerated` was still correct** — only the ingestion was late. This is exactly the "dead source vs. late source" difference query 2 is designed to show.
- `Event` by level: Information 488 · Warning 10 · Error 12 (the Information rows are the Security events collected before I removed them from chain A).

### My own RDP logon, seen from the SIEM
| Time (UTC) | Account (New Logon) | LogonType | Source IP | Meaning |
|---|---|---|---|---|
| 2026-10-08 17:17:06 | `mohammed` | 3 | 10.50.0.1 | Network Level Authentication — Windows checks my password over the network first |
| 2026-10-08 17:17:09 | `mohammed` | **10** | 10.50.0.1 | New Remote Desktop session |

`10.50.0.1` is the lab gateway relaying RDP, not my laptop's address. Most other 4624 rows are `NT AUTHORITY\SYSTEM` LogonType 5 (services starting) or `WKS-L51$` LogonType 3 from `::1` (the machine talking to itself) — read **New Logon / TargetUserName**, not **Subject**.

## Step 5b — Chain B: Sentinel connector → `SecurityEvent`

1. Sentinel → **Content management → Content hub** → install **Windows Security Events**. *(If the page says "moved to Defender portal", hard-reload with Ctrl+F5.)*
2. **Configuration → Data connectors → Windows Security Events via AMA** → **Open connector page** → **+ Create data collection rule**. *(Not "[DEPRECATED] Security Events via Legacy Agent".)*
3. Name `dcr-securityevents`, RG `rg-sentinel-lab`, resource `WKS-L51`, events **Common** (the form pre-selects *All Security Events* — changed it).
4. Connector status → **Connected**; `SecurityEvent` rows with `Account`, `LogonType`, `IpAddress` columns.

Verified in the DCR JSON: stream `Microsoft-SecurityEvent`, an explicit list of event IDs + AppLocker channels (that is the *Common* set — *All* would just be `Security!*`), destination `log-sentinel-lab-1`, tag `createdBy: Sentinel`.

### Chain A vs chain B

| | Chain A — `dcr-windowsevents` → `Event` | Chain B — `dcr-securityevents` → `SecurityEvent` |
|---|---|---|
| Created from | Azure Monitor (works without Sentinel) | Sentinel connector (needs the *Windows Security Events* solution) |
| Can collect | any Windows log (Application, System, Security…) | Security log only |
| Event selection | by log + level (XPath for advanced) | ready-made sets: All / Common / Minimal / Custom |
| Shape of data | one text blob (`RenderedDescription`) — parse it yourself | already split into columns (`Account`, `LogonType`, `IpAddress`…) |
| Sentinel rules / workbooks | mostly not written for it | written for it |
| Typical user | IT operations (system/app health) | SOC / security team |
| Cost | per GB ingested | same — and with both on, **every security event is paid twice** |

### Removing the duplicate
Monitor → Data Collection Rules → `dcr-windowsevents` → Windows Event Logs → **untick Security (Audit success, Audit failure)** → Save. Application and System stay in chain A.

Check: the newest 4624 in `Event` is **2026-10-07 21:58 UTC** and nothing has arrived since, while `SecurityEvent` keeps receiving new 4624s (latest seen 2026-10-08 18:41 UTC). Current chain A JSON contains only `Application!*[...Level=1,2,3]` and `System!*[...Level=1,2,3]`.

**Why I kept only chain B for the Security log (in my own words):** one fact should live in one place. With both chains, the same logon sits in two tables, I pay for it twice, and an analyst can search the "wrong" table and get a different answer. `SecurityEvent` is the table Sentinel's detection rules, hunting queries and workbooks are built on, and its columns let me filter on `LogonType` or `Account` directly instead of parsing text. Chain A still earns its place for Application and System health logs, which chain B cannot collect.

## Troubleshooting checklist (for the next person)

1. No data? → `Heartbeat` first.
2. `RequestDisallowedByAzure` + *policy/location* → region not on your allowed list.
3. `RequestDisallowedByAzure` + *MFA* → re-run `azcmagent connect … --use-device-code`, enter the code on your laptop.
4. Arc script fails with a meaningless `(400) Bad Request` → admin window? `Set-ExecutionPolicy -Scope Process Bypass` in the same window? allowed region?
5. Workspace name refused → pick a variant (`-1`) and use it consistently.
6. Allow 15–30 min after creating a DCR before expecting rows; after 45 min with no heartbeat, escalate.
