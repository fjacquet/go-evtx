# Windows VM for local EVTX verification

## Why this exists

go-evtx writes `.evtx` files, and the only authority on whether a `.evtx` file is valid is the Windows Event Log API. That API lives in `wevtapi.dll` and is Windows-only — verified on this project's development machine:

```console
$ pwsh -NoProfile -c '[System.Diagnostics.Eventing.Reader.EventLogQuery]::new($p, "FilePath")'
FAILED: EventLog access is not supported on this platform.
```

PowerShell 7 runs fine on macOS and the .NET type resolves, because the class ships in the assembly. The implementation P/Invokes into a DLL that does not exist on Darwin. `Get-WinEvent` is not even present as a cmdlet on Unix.

So every format hypothesis has had to go through a GitHub Actions `windows-latest` runner: roughly five minutes per experiment. The v0.7.0 format investigation spent more than twenty such round trips. A local Windows VM turns that into seconds.

**This does not replace CI.** The `Format Verify` workflow remains the shared, reproducible record behind `docs/format-baseline.md`, and it runs on a clean Windows image. The VM replaces the *waiting between ideas*, not the proof.

## Prerequisites

- Apple Silicon Mac (this guide assumes ARM; the same steps work on x86 hosts)
- A virtualisation host: UTM (free) or Parallels Desktop
- A Windows 11 ARM installation in that VM
- An SSH keypair on the Mac (`ssh-keygen -t ed25519` if you do not already have one)

## VM side

Run everything below in an **elevated** PowerShell session inside the VM.

### 1. Install PowerShell 7

Windows ships PowerShell 5.1, which is not what CI uses and behaves differently. Install 7:

```powershell
winget install --id Microsoft.PowerShell --source winget
```

Confirm the install path — the rest of this guide assumes the default:

```powershell
Get-Command pwsh | Select-Object -ExpandProperty Source
# C:\Program Files\PowerShell\7\pwsh.exe
```

### 2. Enable the OpenSSH server

It ships with Windows 11 as an optional feature; nothing external is needed.

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

Confirm it is listening:

```powershell
Get-Service sshd
Get-NetTCPConnection -LocalPort 22 -State Listen
```

### 3. Open the firewall

The capability usually adds the rule, but verify rather than assume — a missing rule looks exactly like a network problem from the Mac:

```powershell
Get-NetFirewallRule -Name *OpenSSH-Server* | Select-Object Name, Enabled, Direction, Action
```

If it is absent:

```powershell
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 4. Make `pwsh` the default shell

Without this, SSH drops you into `cmd.exe` and every command needs a `powershell -c` wrapper.

```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell `
  -Value "C:\Program Files\PowerShell\7\pwsh.exe" -PropertyType String -Force
```

The `HKLM:\SOFTWARE\OpenSSH` key exists once the server capability is installed. If `New-ItemProperty` fails because the key is missing, step 2 did not complete.

### 5. Authorise your public key — the step that silently fails

**For a member of the Administrators group, Windows does not read `~/.ssh/authorized_keys`.** It reads a single shared file:

```
C:\ProgramData\ssh\administrators_authorized_keys
```

This trips up nearly everyone. Worse, when the file's permissions are wrong, `sshd` ignores it **without logging anything at the default log level** — you get a password prompt and no explanation.

Create it with your public key, then fix the ACL:

```powershell
$key = 'ssh-ed25519 AAAA... you@mac'   # contents of ~/.ssh/id_ed25519.pub on the Mac
$f = 'C:\ProgramData\ssh\administrators_authorized_keys'
Set-Content -Path $f -Value $key -Encoding utf8

icacls $f /inheritance:r
icacls $f /grant 'Administrators:F' /grant 'SYSTEM:F'
```

`/inheritance:r` is the part that matters: it strips inherited entries. The file must grant access to **only** `Administrators` and `SYSTEM`. Any other principal — including your own user account — makes `sshd` reject the file.

Verify:

```powershell
icacls $f
# Expect exactly: BUILTIN\Administrators:(F) and NT AUTHORITY\SYSTEM:(F)
```

If you use a **non-administrator** account instead, the conventional `C:\Users\<you>\.ssh\authorized_keys` applies and needs no special ACL. That is arguably the cleaner setup, at the cost of needing elevation for some diagnostics.

### 6. Find the VM's address

```powershell
ipconfig
```

Take the IPv4 address on the adapter your hypervisor provides. Parallels' shared network and UTM's "Shared Network" mode both give the VM an address reachable from the host.

## macOS side

Add an entry to `~/.ssh/config`:

```
Host winvm
    HostName 10.211.55.x        # from ipconfig above
    User your-windows-account
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
```

Verify the whole chain in one command:

```console
$ ssh winvm 'pwsh -NoProfile -c "$PSVersionTable.PSVersion.ToString(); [Environment]::OSVersion.VersionString"'
7.5.4
Microsoft Windows NT 10.0.26100.0
```

If that prints a PowerShell 7 version and a Windows build, everything above worked.

## The verification loop

With SSH working, a format experiment becomes:

```bash
# 1. Generate a fixture locally
go run ./cmd/gen-fixture-minimal -out /tmp/probe

# 2. Copy it over
scp /tmp/probe/generated.evtx winvm:C:/probe/generated.evtx

# 3. Ask Windows
ssh winvm 'pwsh -NoProfile -c "
  $q = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
         \"C:\probe\generated.evtx\",
         [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
  $r = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($q)
  $e = $r.ReadEvent()
  try { $null = $e.ToXml(); \"ToXml ok\" }
  catch { \"ToXml FAILED - \" + $_.Exception.Message }
"'
```

Seconds instead of a CI round trip.

**Keep recording results in CI.** A verdict from the VM is a fast signal for iterating; a row in `docs/format-baseline.md` must cite a CI run, selected by `head_sha`, per the measurement-discipline rules in `CLAUDE.md`. The VM and the record serve different purposes and the distinction has already mattered once in this project.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Password prompt despite a correct key | ACL on `administrators_authorized_keys` is wrong. Re-run the `icacls` commands; `sshd` fails closed and silently |
| Lands in `cmd.exe` | The `DefaultShell` registry value is missing or points at a path that does not exist |
| Connection times out | Firewall rule absent, or the hypervisor is in "Host-Only" mode with no route from the Mac |
| `Add-WindowsCapability` fails | Not running elevated, or Windows Update is mid-operation |
| `ToXml` succeeds in the VM but the CI job fails | Different Windows build. Trust CI for the record and investigate the divergence — it is itself informative |

To see why `sshd` rejected an authentication, raise its log level in `C:\ProgramData\ssh\sshd_config` (`LogLevel DEBUG3`), restart the service, and read `C:\ProgramData\ssh\logs\sshd.log`.

## Security

Key authentication only — leave `PasswordAuthentication no` in `sshd_config`. Keep the VM on your hypervisor's shared or host-only network rather than bridging it onto the LAN. This is a disposable test machine, but an SSH server is an SSH server.
