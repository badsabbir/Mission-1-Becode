# Detection — Step 6: something I did not do

**Machine:** `WKS-L51.hamilton.corp`   **Workspace:** `log-sentinel-lab-1`   **Table:** `SecurityEvent`

## What I found

On **2026-10-08 at 09:14:12 UTC** (11:14 Brussels time), the program **`C:\Windows\System32\net1.exe`** enumerated the members of the local **Administrators** group on my workstation, running as **SYSTEM**. That is the trace left by a command such as `net localgroup administrators` — a classic first reconnaissance step ("who are the admins on this box?").

## How I found it

1. Listed every security event type over 7 days, rarest first. No account creation (4720), failed logon (4625), lockout (4740) or log clearing (1102) — so I looked at the rarer, quieter IDs.
2. **4798 / 4799** ("local user / group membership was enumerated") is fired by normal Windows components, so I grouped it by **calling process**. Every caller was a known system process (`svchost.exe`, `VSSVC.exe`, `SearchIndexer.exe`, `qemu-ga.exe`, `CompatTelRunner.exe`) — **except one row: `net1.exe`, count 1.**
3. Zoomed into the 3 minutes around it:

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-08 09:13) .. datetime(2026-10-08 09:16))
| project TimeGenerated, EventID, SubjectUserName, SubjectLogonId, TargetUserName,
          CallerProcessName, CallerProcessId, LogonType, LogonProcessName
| order by TimeGenerated asc
```

## Result

| Time (UTC) | EventID | Subject | LogonId | Target | Caller process |
|---|---|---|---|---|---|
| 09:14:10.171 | 4624 + 4672 | WKS-L51$ | 0x3e7 | SYSTEM (LogonType 5, via `services.exe`) | — |
| **09:14:12.153** | **4799** | **WKS-L51$** | **0x3e7** | **Administrators** | **`C:\Windows\System32\net1.exe`** (PID 0x5ac) |
| 09:14:14.356 | 4624 + 4672 | WKS-L51$ | 0x3e7 | SYSTEM (LogonType 5) | — |
| 09:14:14.395 | 4799 | WKS-L51$ | 0x3e7 | Administrators, Backup Operators | `svchost.exe` |
| 09:14:14.442 | 4624 + 4672 | WKS-L51$ | 0x3e7 | SYSTEM (LogonType 5) | — |

## Why I know I did not do this

- **Nobody was logged on interactively.** My last session ended on 2026-10-07 at 23:11 UTC (4647 logoff, then shutdown). The machine booted at 08:42 UTC. My next logon is **17:17 UTC** (LogonType 3 then 10 from 10.50.0.1). Between those, there is **no 4624 for any human account** — only SYSTEM/machine-account logons.
- **It ran as SYSTEM (`0x3e7`), not as me.** If I had typed `net localgroup` in my RDP session, the subject would be `mohammed` with my own logon ID.
- **It was started by a service.** A SYSTEM logon from `services.exe` two seconds before, then `net1.exe` — that is the pattern of a command pushed to the machine and executed by a service or management agent, not by a person at the keyboard.
- **It happened once.** Every other caller of 4799 repeats dozens of times (normal background activity); `net1.exe` appears exactly once in 7 days.

## What I think happened

At about 09:14 UTC the coach pushed a command to all workstations at once, through a remote-execution channel that runs as SYSTEM (for example the hypervisor's guest agent — `qemu-ga.exe` is present on the machine — or a service-based tool like PsExec). The command was **`net localgroup administrators`** (or similar), which Windows records as `net1.exe` reading the Administrators group.

## Limits — what I could not see

- **No process-creation record (4688) for `net.exe` / `net1.exe`.** 4688 only appears at boot, so command-line auditing is not effectively on: I can see *that* `net1.exe` read the group, but not the exact command line or which parent process launched it.
- **No service-install event.** 7045 (System log) is *Information* level, which chain A does not collect; 4697 did not appear in `SecurityEvent`.
- So "the coach did it remotely" is my **best explanation, not a proven fact**. To confirm I would: ask the coach for the time and method, enable process-creation auditing with command lines, and collect System-log *Information* events for 7045.
