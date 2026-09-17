# Defender WSC Race Condition Remediation

PowerShell detection and remediation script for a Windows Security Center (WSC) registration race condition where Microsoft Defender is operational but WSC reports an incorrect product state.

## Problem

Under certain conditions Microsoft Defender remains fully active:

- AMRunningMode = Normal
- AMServiceEnabled = True
- AntivirusEnabled = True
- RealTimeProtectionEnabled = True

However, Windows Security Center reports:

- WMI productState = `0x060100`
- Registry STATE = `0x060100`

This results in Windows reporting that antivirus protection is disabled even though Defender is functioning normally.

## What the Script Does

The script:

1. Collects Defender health information.
2. Collects Security Center WMI information.
3. Reads Defender Security Center registry state.
4. Detects the known broken state (`0x060100`).
5. Verifies Defender is actually healthy.
6. Attempts WSC recovery by ensuring `wscsvc` is running.
7. Executes:

```powershell
MpCmdRun.exe -ResetPlatform
```

8. Monitors state recovery.
9. Logs all actions.

## Requirements

- Windows PowerShell 5.1+
- Local Administrator or SYSTEM
- Microsoft Defender Antivirus installed

## Usage

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\Defender_Remediation.ps1
```

## Expected Healthy State

| Component | Value |
|------------|---------|
| WMI Product State | 0x061100 |
| Registry STATE | 0x061100 |
| AMRunningMode | Normal |
| AntivirusEnabled | True |
| RealTimeProtectionEnabled | True |

## Logging

Logs are written to:

```text
C:\ProgramData\DefenderWscRace\DefenderWscRace.log
```

## Exit Codes

| Code | Meaning |
|--------|---------|
| 0 | Healthy or successfully remediated |
| 1 | Broken state detected, remediation failed, or Defender not healthy |

## Disclaimer

Test in a controlled environment before broad deployment.
