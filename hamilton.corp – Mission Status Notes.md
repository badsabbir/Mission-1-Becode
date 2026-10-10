# hamilton.corp – Mission Status Notes

Oct 9, 2026 · @Aminul Haque

Category 1 is nearly complete; Category 2 still needs the Security log, read from an administrator PowerShell on WKS-L51.

## First: get the CTFd questions

"Know your seat" and "What just happened?" are categories. Inside each, CTFd lists specific challenges, each with its own question and a flag in `HAM{...}` format. Without the question text, it is impossible to say which finding answers which challenge.

1. In CTFd, click **Challenges**.
2. Open each challenge under the two categories.
3. Copy the question text into these notes, then match it to a finding below.

## Know your seat

All answers below are proven by a command run on WKS-L51.

| Question | Answer | Proof (command) |
| --- | --- | --- |
| Who am I? | `hamilton\mohammed` (domain account) | `whoami` |
| My SID | `S-1-5-21-1998217823-27113373-1563206344-1144` | `whoami /user` |
| Where is my user? | `CN=mohammed,OU=Accounts,DC=hamilton,DC=corp` | `whoami /fqdn` |
| Which machine? | `WKS-L51` | `hostname` |
| Where is my computer? | `CN=WKS-L51,OU=L51,OU=Learners,DC=hamilton,DC=corp` | `([adsisearcher]"(cn=$env:COMPUTERNAME)").FindOne().Path` |
| Who checked my password? | `DC01` (`DC01.hamilton.corp`) | `echo $env:LOGONSERVER` |
| GPOs on my user | None applied | `gpresult /r` |
| GPOs on my computer | Not visible yet (needs admin) | `gpresult /r /scope computer` |
| Local admins on WKS-L51 | `HAMILTON\Domain Admins`, `HAMILTON\mohammed`, `WKS-L51\Administrator` (disabled), `WKS-L51\becode` | `Get-LocalGroupMember -Group Administrators` |
| Am I a local admin? | Yes, but UAC limits it: Administrators shows "deny only" until PowerShell runs as administrator | `whoami /groups` |

My user (`OU=Accounts`) and my computer (`OU=Learners\L51`) sit in different branches of the tree, so they receive different GPOs.

Local accounts `helpdesk` and `labuser` are labelled for Mission 2. Note only; do not touch them yet.

## What just happened?

An admin-level identity wrote the sheet to the Public Desktop of WKS-L51 on 8 Oct 2026 at 11:11:25; which account, how, and from where are not yet proven.

### Proven

- `IDENTITY_IN_HAMILTON.md` is in `C:\Users\Public\Desktop`, not in `C:\Users\mohammed\Desktop`. Every user of WKS-L51 sees it.
- CreationTime and LastWriteTime are both 08-10-26 11:11:25 (date format confirmed as day-month-year). The file was written in one go.
- On the Public Desktop folder, `NT AUTHORITY\INTERACTIVE` has only ReadAndExecute; only SYSTEM and Administrators have FullControl. Only an admin-level identity could write there.
- Owner is `BUILTIN\Administrators`. This confirms admin level but does not name the person, and does not rule out SYSTEM.
- LastAccessTime (09-10-26 00:45:18) is my own access during the investigation: contaminated, not evidence.
- `CTFD_CREDENTIALS.txt` is missing from both Desktop folders. `C:\Users\mohammed\AppData\Roaming\Microsoft\Windows\Recent\CTFD_CREDENTIALS.lnk` proves `mohammed` opened it.

### Suspects (members of local Administrators, plus SYSTEM)

| Suspect | Type | Note |
| --- | --- | --- |
| `HAMILTON\Domain Admins` | Domain group | Fits "from outside your machine" |
| `WKS-L51\becode` | Local account, enabled | Usable remotely if its password is known |
| `WKS-L51\Administrator` | Local account | Disabled now; status on 8 Oct unknown |
| `HAMILTON\mohammed` | My own account | Must be ruled out with evidence |
| SYSTEM | Built-in | Would point to a GPO or scheduled task |

### Not yet proven

- Which exact account wrote the sheet
- The method: GPO, network copy to `C$`, or script
- The source machine
- Where the credentials file was, and where it went
- Why `HAMILTON\mohammed` can delete files on the Public Desktop
- Who owns SIDs `S-1-5-21-2439867544-482898458-1306205539-1001` and `-1004`. Their prefix differs from the domain SID, so they are local accounts, possibly deleted or from a template machine

## Next moves

The answer to "who and how" is in the Security log of WKS-L51, and only an administrator PowerShell can open it.

- [ ] Paste the CTFd challenge questions into these notes
- [ ] Open PowerShell as administrator (right-click, Run as administrator)
- [ ] Run `whoami /groups` again and record the UAC difference (High Mandatory Level)
- [ ] Run `gpresult /r /scope computer` to see the computer GPOs
- [ ] Run `Get-LocalUser | Select-Object -Property Name, SID, Enabled` and compare with the `-1001` / `-1004` SIDs
- [ ] Read the shortcut target of `CTFD_CREDENTIALS.lnk` to find where the credentials file was
- [ ] Query event 4624 from 11:06 to 11:16 on 8 Oct 2026; note Logon Type, User, Domain and Source IP
- [ ] Resolve the Source IP to a machine name with `Resolve-DnsName`

### Rules to keep

- Record nothing as evidence without the command that produced it.
- State what could not be proven in a Gaps section.
- Rule out every suspect with evidence, including my own account.
- Repeating the mission text does not move the investigation; running the next command does.
