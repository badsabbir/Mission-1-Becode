# CTF – Mission 01 (hamilton.corp)

Aminul Haque (Sabbir) · BeCode · Seat **WKS-L51** · Account `hamilton\mohammed`

⚠️ = run PowerShell **as administrator** (right-click → Run as administrator)

| My seat | |
| --- | --- |
| Domain | `hamilton.corp` (short name: HAMILTON) |
| Workstation | `WKS-L51` (`WKS-L51.hamilton.corp`) |
| Domain controller | `DC01` (`10.50.0.10`) |
| Workstation OU | `OU=L51,OU=Learners,DC=hamilton,DC=corp` |
| User account OU | `Accounts` |
| GPO applied | `Default Domain Policy` |

---

## 0. Hello CTFd

### Hello CTFd

**Hints:** none.

**How I did it:**
1. Opened `IDENTITY_IN_HAMILTON.md` on the Public Desktop.
2. Read the flag on the last line.

**Result:** `HAM{identity_first}`. A test flag; the lesson is to find out *who* first.

---

## Part 1: Know your seat

### 1. My workstation's full name

*What is the full name (short name + domain) of your workstation?*

**Hint 1:** The full name is the short name of the computer, followed by a dot and the name of the domain.
**Hint 2:** Windows shows this in the system information, under the device name and the domain.

**How I did it:**
1. Opened PowerShell.
2. Asked Active Directory for my computer's full name:
   `([adsisearcher]"(cn=$env:COMPUTERNAME)").FindOne().Properties.dnshostname`
3. Output: `WKS-L51.hamilton.corp`.

**Result:** `HAM{WKS-L51.hamilton.corp}`

### 2. Who vouched for me?

*Which server checked your password? Give its short name.*

**Hint 1:** Re-read idea 2 of the sheet. The server has a role with a name.
**Hint 2:** Windows remembers which server handled your logon, as an environment variable.

**How I did it:**
1. Ran `$env:LOGONSERVER` in PowerShell.
2. Output: `\\DC01`. Removed the backslashes.

**Result:** `HAM{DC01}`. DC01 is the domain controller: the server that says "yes, this is really mohammed."

### 3. Where does it live?

*What is the IP address of the server from challenge 2?*

**Hint 1:** A name can be turned into an address by asking DNS (the network's phone book).

**How I did it:**
1. Ran `Resolve-DnsName -Name DC01.hamilton.corp`, which gave `10.50.0.10`.
2. Double-checked with `nltest /dsgetdc:hamilton.corp` (`/dsgetdc` = "find the domain controller"), which gave the same IP.

**Result:** `HAM{10.50.0.10}`. Two independent commands agree, so it's proof, not a claim.

### 4. My workstation's place in the tree

*Give the full path of your computer's OU, written as a distinguished name.*

**Hint 1:** A distinguished name reads from most specific to most general, separated by commas (e.g. `OU=Laptops,DC=example,DC=corp`).
**Hint 2:** The group policy report names the computer object and where it sits. The computer part needs an elevated prompt.

**How I did it:**
1. Ran `([adsisearcher]"(cn=$env:COMPUTERNAME)").FindOne().Path`.
2. Output: `LDAP://CN=WKS-L51,OU=L51,OU=Learners,DC=hamilton,DC=corp`.
3. Removed `LDAP://` and `CN=WKS-L51,` (the computer itself, not its OU).

**Result:** `HAM{OU=L51,OU=Learners,DC=hamilton,DC=corp}`

### 5. My account's place in the tree

*In which OU is your user account stored? Give only its name.*

**Hint 1:** Compare where your account lives with where your workstation lives. Same place?

**How I did it:**
1. Ran `whoami /fqdn` (`/fqdn` = show my full path in Active Directory).
2. Output: `CN=mohammed,OU=Accounts,DC=hamilton,DC=corp`.

**Result:** `HAM{Accounts}`. My user and my computer are in different OUs, so they can receive different rules.

### 6. The rules that reach me

*Which GPO is applied to your workstation? Give its exact name.*

**Hint 1:** The report lists the GPOs applied to the computer, and those filtered out.
**Hint 2:** A GPO linked at the very top of the tree reaches every computer below it.

**How I did it:**
1. Opened PowerShell as administrator ⚠️.
2. Ran `gpresult /r /scope computer` (`/r` = summary report; `/scope computer` = computer rules only).
3. Read "Applied Group Policy Objects".

**Result:** `HAM{Default Domain Policy}`

### 7. Local power, domain identity

*Your local Administrators group also contains a domain group. Which one?*

**Hint 1:** Look at the members of the local Administrators group and how each is written.
**Hint 2:** A member with the domain name in front is a domain identity. Your own account is one; there is another.

**How I did it:**
1. Ran `Get-LocalGroupMember -Group Administrators`.
2. Members: `HAMILTON\Domain Admins`, `HAMILTON\mohammed`, `WKS-L51\Administrator` (disabled), `WKS-L51\becode`.

**Result:** `HAM{Domain Admins}`. Anyone added to Domain Admins on DC01 instantly controls my PC.

**Before you leave:** *Which answers came from the workstation, and which from the domain?*
> ✍️ Write your own answer here.

---

## Part 2: What just happened?

`IDENTITY_IN_HAMILTON.md` appeared in `C:\Users\Public\Desktop` on **08-10-2026 at 11:11:25**. No one logged in to put it there.

### 8. Whose file is it?

*Who owns the sheet? Write it the way Windows writes it, with the part before the backslash.*

**Hint 1:** The owner is part of the file's security settings.
**Hint 2:** Re-read idea 1 of the sheet. The owner is not you, and not a person.

**How I did it:**
1. Ran `(Get-Acl -Path "C:\Users\Public\Desktop\IDENTITY_IN_HAMILTON.md").Owner`.
2. Output: `BUILTIN\Administrators`.
3. Kept the part before the backslash, as the question asks.

**Result:** `HAM{BUILTIN}`. (If CTFd accepted `HAM{BUILTIN\Administrators}` from you, record that instead.) Note that the Properties window shows `WKS-L51\Administrators`, which is the wrong prefix; `Get-Acl` shows how Windows really writes it.

### 9. Which program wrote it?

*Nobody opened a session, yet the file was written. Which program did it?*

**Hint 1:** Look at what was logged around the time the file was created.
**Hint 2:** Your workstation is a virtual machine. Its manager installed a small program inside it to talk to the machine from outside.

**How I did it:**
1. Opened PowerShell as administrator ⚠️.
2. Searched **every** log from 2 minutes before to 3 minutes after the file's creation time:
   ```powershell
   $t = Get-Date "2026-10-08 11:11:25"
   Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
     Where-Object { $_.RecordCount -gt 0 } |
     ForEach-Object {
       Get-WinEvent -FilterHashtable @{ LogName = $_.LogName; StartTime = $t.AddMinutes(-2); EndTime = $t.AddMinutes(3) } -ErrorAction SilentlyContinue
     } |
     Sort-Object -Property TimeCreated |
     Select-Object -Property TimeCreated, LogName, Id, ProviderName |
     Format-Table -AutoSize
   ```
3. Found the event at 11:11:25 with ProviderName `qemu-ga`.
   > 📋 Paste the output line here.

**Result:** `HAM{qemu-ga}`. The QEMU Guest Agent lets the host server write files and run commands inside the VM with no login.

### 10. Where was it written down?

*In which Windows log did you find the trace of that program?*

**Hint 1:** It is not the Security log.

**How I did it:**
1. Read the `LogName` column on the `qemu-ga` line of the sweep.
2. Ruled out Sysmon (not installed) and a remote tool installing a service (no event 7045).

**Result:** `HAM{Application}`

**Before you leave:** *Look for the same trace in your SIEM. What do you find, and why?*
> ✍️ Write your own answer here. Run the search in your SIEM first.

---

## Part 3: Something changed (the intrusion)

### 11. A new identity

*A new account exists on your workstation. What is its name?*

**Hint 1:** Re-read idea 1. Local or domain account? That tells you where to look.
**Hint 2:** Compare with what you noted in Know your seat. Look at when each account was created.

**How I did it:**
1. Ran `Get-LocalUser` and compared with my baseline.
2. New account: `svc_backup`. (`helpdesk` and `labuser` were already there, from earlier lab setups.)

**Result:** `HAM{svc_backup}`. A boring "backup" name is exactly how attackers hide a way back in.

### 12. What it can do

*That account is in a local group giving full control. Which group?*

**Hint 1:** You already looked at this group in Know your seat. Look again.

**How I did it:**
1. Ran `Get-LocalGroupMember -Group Administrators`.
2. `WKS-L51\svc_backup` is now in the list.

**Result:** `HAM{Administrators}`. A new account with full control is a backdoor.

### 13. The SIEM saw the creation

*Find the event that recorded the account's creation. What is its Event ID?*

**Hint 1:** Search your workstation's security events around the creation time; look for account management activity.

**How I did it:**
1. Searched the SIEM for the account name, then read the event code.
2. Filter: `event.code : 4720` = "A user account was created."

**Result:** `HAM{4720}`

### 14. The SIEM saw the promotion

*Find the event that recorded the account being added to that group. What is its Event ID?*

**Hint 1:** It happened a few seconds after the creation, on the same machine.

**How I did it:**
1. Same search as challenge 13.
2. Found the event a few seconds later: `event.code : 4732` = "A member was added to a security-enabled local group."

**Result:** `HAM{4732}`. Creation (4720) followed by promotion (4732) is the pattern that should trigger an alert.

### 15. Bonus: you changed too

*Your domain account is now in a new domain group. What is it?*

**Hint 1:** Re-read idea 2. A change to a domain account is made in the directory. Ask the domain.
**Hint 2:** Your session's groups were fixed when you logged on. Sign out and back in, then compare.

**How I did it:**
1. Asked Active Directory directly (no sign-out needed):
   `([adsisearcher]"(samaccountname=$env:USERNAME)").FindOne().Properties.memberof`
2. Compared with my baseline and found the new group.

**Result:** `HAM{L51-Project-Readers}`. `whoami /groups` misses it until you log in again.

### 16. Bonus: who wrote it down?

*Which machine recorded the change to your domain account in its security log?*

**Hint 1:** Who manages domain accounts? Not your workstation.

**How I did it:**
1. Found the group-change event in the SIEM.
2. Read its `host` field: `DC01`.

**Result:** `HAM{DC01}`. Domain changes are logged on the domain controller, not on my PC.

**Before you leave:** *For each of the three changes (file on Desktop, new account, new group): where does the evidence live, and could your SIEM see it? What does that say about what your SIEM covers?*

| Change | Where the evidence lives | Could my SIEM see it? |
| --- | --- | --- |
| File on the Public Desktop (written by `qemu-ga`) | WKS-L51, **Application** log (`qemu-ga` provider) | **Probably not.** The SIEM collects the Security log, not Application. *(Verify: search the SIEM for `qemu-ga` around 08-10-2026 11:11:25.)* |
| New local account `svc_backup`, added to Administrators | WKS-L51, **Security** log (4720 creation, 4732 group add) | **Yes.** Both events found in the SIEM. |
| My domain account added to `L51-Project-Readers` | **DC01**, Security log | **Yes, if** the group-change event really showed `host: DC01` in my SIEM. *(Verify: if I only deduced DC01 without seeing the event, the answer is "No, DC01 does not send its logs".)* |

**What this tells me:** my SIEM only sees what it is told to collect, from the machines that send it logs. It caught the change in the Security log of my workstation. It most likely missed the file drop, because that trace was in the Application log. So a quiet action from the host server (no login, no Security event) can go unseen. And a change to my own domain account is only visible if the domain controller ships its logs too. **A blind spot in collection is a blind spot in detection.**
