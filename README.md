# SSH Brute-Force Simulation, Log Analysis and Windows Server Hardening

## Practical Lab Script and Demonstration Guide

**Project category:** Defensive security / incident investigation\
**Lab systems:** Kali Linux (test machine) and Windows Server (OpenSSH
target)\
**Main tools:** OpenSSH, Hydra, PowerShell, Windows Event Viewer and
Windows Defender Firewall\
**Network addresses recorded in the project report:** Windows Server
`10.0.0.5`; Kali Linux `10.0.0.6`

> **Authorisation and safety:** Perform every attack simulation only in
> your own isolated lab or on systems for which you have explicit
> written permission. Do not use this procedure against public IP
> addresses, workplace systems or third-party networks. Use disposable
> lab accounts and passwords, and remove them when testing is complete.

------------------------------------------------------------------------

## 1. Project purpose

This lab demonstrates how to:

1.  Configure and verify OpenSSH on Windows Server.
2.  Create a dedicated test account and verify remote SSH access.
3.  Generate controlled SSH authentication failures from Kali Linux
    using Hydra.
4.  Investigate Windows Security events for failed and successful
    logons.
5.  Assess whether the test activity resulted in unauthorised access.
6.  Harden SSH and restrict access using Windows Firewall.
7.  Validate the defensive changes and document the results.

The objective is to understand both the attacker activity visible in a
controlled simulation and the defensive investigation performed by a
system administrator or security analyst.

## 2. Lab layout

  Component                  Role                             Address in the report
  -------------------------- -------------------------------- -----------------------
  Windows Server 2019/2022   SSH target                       `10.0.0.5`
  Kali Linux                 Test/attack simulation machine   `10.0.0.6`

Both virtual machines should be connected to the same isolated lab
network. Confirm the addresses before running commands; virtual lab
addresses can change.

### Verify network configuration

**On Windows Server -- Administrator PowerShell:**

``` powershell
ipconfig
```

**On Kali Linux:**

``` bash
ip addr
```

**From Kali, test connectivity to Windows:**

``` bash
ping -c 4 10.0.0.5
```

Expected outcome: the Windows host responds to the ping, assuming ICMP
is permitted by the lab firewall.

**Evidence to save:** screenshots showing both IP configurations and the
successful connectivity test.

## 3. Phase 1 -- Install and configure OpenSSH Server

Run the following commands in an elevated Windows PowerShell session.

### 3.1 Check OpenSSH capability status

``` powershell
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
```

Review the output to determine whether the OpenSSH Server capability is
installed.

### 3.2 Install OpenSSH Server if it is not installed

``` powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

Wait for installation to complete.

### 3.3 Start SSH and configure automatic startup

``` powershell
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
Get-Service sshd
```

Expected outcome: the `sshd` service should show as running.

### 3.4 Allow inbound SSH through Windows Firewall

The project report records a firewall rule for TCP port 22. Use this
PowerShell syntax:

``` powershell
New-NetFirewallRule `
  -Name "sshd" `
  -DisplayName "OpenSSH Server" `
  -Enabled True `
  -Direction Inbound `
  -Protocol TCP `
  -Action Allow `
  -LocalPort 22
```

If a rule with this name already exists, inspect it rather than creating
duplicate rules:

``` powershell
Get-NetFirewallRule -Name "sshd"
```

**Evidence to save:** OpenSSH capability status, running service and
firewall rule.

## 4. Phase 2 -- Create a dedicated test account and verify SSH

Use a disposable, non-administrative account for the lab. The report
used the account name `testuser1` and a separate account named
`adminuser`. Do not reuse the example passwords from any report or use
real organisational credentials.

### 4.1 Create a lab-only user

In elevated Windows PowerShell:

``` powershell
$Password = Read-Host "Enter a temporary lab password" -AsSecureString
New-LocalUser -Name "testuser1" -Password $Password -Description "Temporary SSH lab account"
```

If you also need the second account described in the report:

``` powershell
$Password = Read-Host "Enter a temporary lab password for adminuser" -AsSecureString
New-LocalUser -Name "adminuser" -Password $Password -Description "Temporary SSH lab account"
```

Verify the accounts:

``` powershell
Get-LocalUser
```

### 4.2 Test SSH from Kali

From Kali:

``` bash
ssh testuser1@10.0.0.5
```

Accept the host key only after confirming that the destination is your
Windows lab server. Enter the temporary lab password when prompted.

Expected outcome: an authenticated remote command-line session opens.
Type `exit` to close it.

**Evidence to save:** successful SSH login and the Windows account list.
Do not include passwords in screenshots.

## 5. Phase 3 -- Simulate SSH password-guessing activity in the lab

This phase creates repeated failed authentication attempts against the
lab Windows Server. It is included to generate events for defensive
monitoring and log investigation.

### 5.1 Check Hydra availability on Kali

``` bash
hydra -h
```

### 5.2 Prepare a small, controlled test wordlist

For a portfolio demonstration, use a short list of dummy passwords
created specifically for the lab. This avoids unnecessary high-volume
attempts and avoids publishing a large password dump.

``` bash
cat > lab-passwords.txt <<'EOF'
IncorrectLabPassword1!
IncorrectLabPassword2!
IncorrectLabPassword3!
EOF
```

### 5.3 Run a limited test against your own lab server

``` bash
hydra -l testuser1 -P ./lab-passwords.txt -t 1 -W 3 ssh://10.0.0.5
```

The command targets the lab account on the lab server only. `-t 1` keeps
the test to one task at a time. Stop the run with `Ctrl+C` if necessary.

**Important:** The original report describes using Kali's `rockyou.txt`
wordlist. A short lab-specific list is preferable for a controlled
demonstration and for a public GitHub portfolio. Do not upload password
dumps or real credential lists to GitHub.

### What to observe

-   Repeated SSH authentication failures from the Kali host.
-   Timestamps of the attempts.
-   The account name being tested.
-   Whether any successful authentication event occurred during the test
    window.

A Hydra result or a failed login event alone does not establish
compromise. Correlate the Windows event records and the exact test time.

**Evidence to save:** the limited test command and terminal output, with
any sensitive information removed.

## 6. Phase 4 -- Investigate Windows Security logs

On Windows Server, open:

**Event Viewer → Windows Logs → Security**

Use **Filter Current Log** to inspect the following event IDs.

### 6.1 Failed logons -- Event ID 4625

Event ID `4625` records a failed logon.

Review the event details for:

-   Account name.
-   Source network address, where recorded.
-   Timestamp.
-   Logon type.
-   Authentication package and failure information.

Compare the timestamps and source address with the controlled Hydra
test. The project report records failed attempts originating from Kali
(`10.0.0.6`).

### 6.2 Successful logons -- Event ID 4624

Event ID `4624` records a successful logon.

Review successful logons during the same time window. Compare the
account, source address and timestamp with the legitimate SSH test and
the simulated attack.

Do not assume every 4624 event is an SSH login. Use the event's details
and surrounding evidence to identify the logon type and authentication
context.

### 6.3 Optional PowerShell log review

Run in elevated PowerShell to retrieve recent events for an initial
review:

``` powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624,4625
    StartTime = (Get-Date).AddHours(-2)
} | Select-Object TimeCreated, Id, ProviderName, Message |
    Format-List
```

Adjust the time window to cover the actual test. Access to Security logs
may require administrative permissions.

**Evidence to save:** examples of relevant 4625 and 4624 events. Redact
usernames, machine identifiers and unrelated information before
publishing.

## 7. Phase 5 -- Assess whether the lab system was compromised

Use the following investigation checklist:

1.  Identify the exact start and end time of the password-guessing test.
2.  Review failed logons (4625) during that period.
3.  Review successful logons (4624) during the same period.
4.  Check whether a successful event corresponds to the test account and
    Kali source address.
5.  Compare any successful event with the known legitimate SSH test.
6.  Record the evidence and explain any uncertainty.

### Finding recorded in the project report

The report states that multiple failed authentication attempts were
observed and that no unauthorised successful login was identified during
the attack simulation.

Use this as the report's stated finding, and make sure it matches the
events in your own lab evidence before presenting it as your result.

## 8. Phase 6 -- Harden the Windows SSH service

The project report applies the following SSH configuration changes.

### 8.1 Back up the SSH configuration

In elevated PowerShell:

``` powershell
Copy-Item "$env:ProgramData\ssh\sshd_config" `
  "$env:ProgramData\ssh\sshd_config.backup"
```

Open the configuration file:

``` powershell
notepad "$env:ProgramData\ssh\sshd_config"
```

### 8.2 Disable password authentication

Set the following directive:

``` text
PasswordAuthentication no
```

This requires key-based authentication for accounts using this SSH
configuration. Before disabling password authentication, configure and
test a working SSH public key for the authorised account and retain
console access to the server. Otherwise, you may lock yourself out.

The project report records the change from the default/commented
password-authentication setting to `PasswordAuthentication no`.

### 8.3 Limit authentication attempts

Add or update:

``` text
MaxAuthTries 3
```

This limits the number of authentication attempts permitted per
connection.

### 8.4 Restrict permitted SSH users

Add or update:

``` text
AllowUsers adminuser
```

This restricts SSH access to the specified account. Ensure that
`adminuser` is the intended authorised account and that its
authentication method has been tested before applying the restriction.

### 8.5 Validate configuration and restart SSH

If the installed Windows OpenSSH build supports the `sshd -t` syntax
check, run:

``` powershell
& "$env:WINDIR\System32\OpenSSH\sshd.exe" -t
```

If the check returns an error, correct the configuration before
restarting the service.

Restart the service:

``` powershell
Restart-Service sshd
Get-Service sshd
```

### 8.6 Restrict SSH access to the Kali lab address

The project report restricts the existing `sshd` firewall rule to the
Kali address:

``` powershell
Set-NetFirewallRule -Name "sshd" -RemoteAddress 10.0.0.6
```

Confirm the rule:

``` powershell
Get-NetFirewallRule -Name "sshd" |
    Get-NetFirewallAddressFilter
```

This allows the lab source address shown in the report. In a real
environment, use the approved management subnet or jump host addresses
and follow organisational firewall policy.

**Evidence to save:** the relevant SSH configuration directives (without
private keys), service status and firewall remote-address restriction.

## 9. Final validation

After hardening, repeat only the authorised, limited tests.

### 9.1 Confirm SSH service status

On Windows:

``` powershell
Get-Service sshd
```

### 9.2 Confirm firewall scope

On Windows:

``` powershell
Get-NetFirewallRule -Name "sshd" |
    Get-NetFirewallAddressFilter
```

### 9.3 Test the approved account

From the permitted lab client, test SSH using the configured key:

``` bash
ssh adminuser@10.0.0.5
```

This assumes that key-based authentication has been configured for
`adminuser`.

### 9.4 Review new Security events

Return to Event Viewer and inspect new 4625 and 4624 events. Confirm
that the observed results match the intended access policy.

The project report states that the hardened configuration reduced the
effectiveness of password-based attempts and restricted access to
authorised users and trusted IPs. Record the actual results of your own
final validation rather than assuming the controls worked.

## 10. Results table

Complete this table using your own evidence before publishing the
project.

  Test                                     Result recorded in the project report
  ---------------------------------------- ---------------------------------------
  SSH service configured successfully      Yes
  Brute-force activity simulated           Yes
  Failed login events detected             Yes
  Unauthorised successful login detected   No
  SSH hardening completed                  Yes
  Firewall restrictions applied            Yes

## 11. Troubleshooting notes

  -----------------------------------------------------------------------
  Symptom                             Checks
  ----------------------------------- -----------------------------------
  Kali cannot ping Windows            Verify both IP addresses, subnet,
                                      virtual network and Windows ICMP
                                      firewall policy.

  SSH connection is refused           Confirm `sshd` is installed and
                                      running; check that TCP 22 is
                                      listening.

  SSH connection times out            Check routing, firewall scope and
                                      whether the target address is
                                      correct.

  Login fails before hardening        Verify the account exists,
                                      credentials are correct and SSH
                                      authentication is enabled.

  Login fails after hardening         Check `AllowUsers`, key placement
                                      and permissions,
                                      `PasswordAuthentication`, and SSH
                                      service logs.

  SSH service will not restart        Validate `sshd_config` syntax and
                                      review the OpenSSH operational
                                      logs.

  No relevant Security events appear  Confirm audit policy/logging, event
                                      time range and permissions; check
                                      OpenSSH operational logs as well.
  -----------------------------------------------------------------------

Useful Windows checks:

``` powershell
Get-Service sshd
Get-NetTCPConnection -LocalPort 22 -State Listen
Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 30
```

## 12. Cleanup

When the exercise is complete:

-   Stop any running test process.
-   Remove the temporary test accounts if they are no longer needed:

``` powershell
Remove-LocalUser -Name "testuser1"
```

Only remove `adminuser` if it was created solely for this lab and is not
needed for administration.

-   Remove the temporary firewall rule if it was created only for this
    exercise:

``` powershell
Remove-NetFirewallRule -Name "sshd"
```

Do this only if you have confirmed the rule is not required by another
OpenSSH configuration. If SSH is intended to remain enabled, replace it
with the approved production firewall rule rather than leaving the
service unintentionally exposed.

-   Restore the SSH configuration from the backup only if you intend to
    undo the hardening changes:

``` powershell
Copy-Item "$env:ProgramData\ssh\sshd_config.backup" `
  "$env:ProgramData\ssh\sshd_config" -Force
Restart-Service sshd
```

-   Securely store or delete lab captures and logs according to your
    lab's data-handling requirements.

## 13. Suggested GitHub repository structure

``` text
ssh-bruteforce-detection-windows-hardening/
├── README.md
├── report/
│   └── Project1.pdf
├── scripts/
│   └── SSH_Brute_Force_Lab_Script.md
└── screenshots/
    ├── 01-network-verification.png
    ├── 02-openssh-installation.png
    ├── 03-ssh-login-test.png
    ├── 04-hydra-lab-simulation.png
    ├── 05-event-id-4625.png
    ├── 06-event-id-4624.png
    ├── 07-ssh-hardening.png
    └── 08-final-validation.png
```

Do not upload real passwords, private SSH keys, sensitive event records,
personal data or large third-party password lists. Review and redact
screenshots before committing them.

## 14. Short presentation script

> "This project demonstrates the detection and prevention of SSH
> password-guessing activity against a Windows Server running OpenSSH. I
> used Kali Linux to verify connectivity and generate a controlled set
> of failed SSH authentication attempts against my lab server. I then
> investigated Windows Security Event IDs 4625 and 4624 to distinguish
> failed logons from successful logons and assess whether unauthorised
> access occurred. After the investigation, I hardened SSH by disabling
> password authentication, limiting authentication attempts, restricting
> permitted users and narrowing the Windows Firewall rule to a trusted
> lab address. Finally, I validated the service and access restrictions.
> This exercise gave me practical experience in security monitoring, log
> analysis, incident assessment and Windows Server hardening."

## 15. Conclusion

The lab demonstrates a defensive workflow for investigating SSH
brute-force activity on Windows Server. It combines controlled attack
simulation, authentication-log analysis, compromise assessment and
system hardening. The key lesson is to correlate authentication events
with timestamps, source addresses and known legitimate activity before
deciding whether a system has been compromised.

**Project note:** This guide is based on the attached capstone report.
Commands and example account handling have been formatted as a reusable
lab script; verify them against your Windows Server version and actual
lab configuration before execution.
