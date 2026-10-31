<div align="center">

# 🌊 OceanSS

**A read-only Minecraft screenshare forensic scanner.**

*Deep artefact collection, execution-proof detection, zero false positives,
and a pitch-black local dashboard — all in one PowerShell file.*

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-black?style=flat-square&logo=windows&logoColor=white)](#)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell&logoColor=white)](#)
[![Version](https://img.shields.io/badge/version-2.0-b30000?style=flat-square)](#)
[![Safety](https://img.shields.io/badge/safety-READ--ONLY-brightgreen?style=flat-square)](#-safety-guarantees)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](#-license)

<img src="logo.svg" width="120" alt="OceanSS logo">

</div>

---

> [!WARNING]
> **Authorized use only.** OceanSS never writes, deletes or kills anything — but running a forensic
> scanner against a machine you do not own or administer may still violate local law or server rules.
> You are responsible for how you use it.

---

## 🎯 What it is

OceanSS is a **single-file PowerShell tool** for Minecraft screenshare / anti-cheat investigations.
It collects execution artefacts from Windows, correlates them against the Minecraft instance's
timeline, scores the evidence, and serves a full forensic dashboard on `localhost`.

It is **purely observational**. There is no payload, no persistence, no registry write, no file
deletion, no process termination — nothing that can damage the machine under examination.

```
  ---------------------------------------------
   Verdict     : LEGIT  (24% risk)
   Detections  : 0  (0 confirmed, 0 source(s))
   Warnings    : 24
   Report      : ~\AppData\Local\Temp\ocean-ss-report-YYYYMMDD-HHmmss.json
  ---------------------------------------------
```

---

## ✨ Features

| | |
|---|---|
| 🕵️ **Execution proof, not file presence** | A file existing proves nothing. OceanSS requires an artefact that proves the thing *ran* — Prefetch, BAM, UserAssist, ShimCache, MuiCache, USN — correlated against `javaw.exe` start time. |
| 🧠 **Constant-pool parsing** | Reads real Java class constant pools instead of grepping raw bytes, so it finds strings that survived obfuscation *and* ignores compression noise that byte-scanning would misreport. |
| ☁️ **Modrinth + CurseForge verification** | SHA-1 lookup against both repos. A jar with a verified hash is whitelisted from obfuscation heuristics — legitimately published mods are not "suspicious". |
| 🧬 **Obfuscator fingerprinting** | Skidfuscator, Radon, Caesium, Bozar, Branchlock, Binscure, QProtect, Zelix, Stringer, JNIC, Scuti, Smoke — plus entropy and fullwidth-Unicode analysis. |
| 🧠 **Safe memory read** | `PROCESS_VM_READ` only, via `ReadProcessMemory`. `javaw.exe` / `explorer.exe` only. Guard pages skipped, size and time budgeted. Never lsass, never csrss. |
| 🖥️ **Local dashboard** | `System.Net.HttpListener` on `localhost:8080`. Pitch-black Ocean Anti-Cheat–style UI: risk gauge, identity PIN, category tabs, timeline, provider status. |
| 📄 **Machine-readable report** | Every scan emits a JSON report you can archive, diff or feed into your own tooling. |
| 🧩 **Zero dependencies** | No modules, no installs, no admin required. One `.ps1` file. |

---

## 🎯 Detection surface

| Registry | Entries | Purpose |
|---|---:|---|
| `CheatStrings` | 127 | In-memory / artefact string needles |
| `JarTokens` | 69 | Tokens hunted inside jar archives |
| `CheatTokens` | 53 | Process, file and path tokens |
| `CheatDomains` | 36 | Known cheat / loader domains (DNS + prefetch + USN) |
| `JarSignatures` | 43 | Structural jar signatures |
| `CheatProcesses` | 31 | Known cheat process names |
| `Obfuscators` | 13 | Obfuscator family markers |
| `BaselinePrefetch` | — | Core vs version-specific Windows prefetch baselines |
| `TrustedSigners` | — | Publishers whose jars skip heuristics |

**Named clients include:** Vape V4 (`Vape421Native.dll`, `.vapeclient`, Teamspeak `tim` key), Prestige
(port `42385`, `prestigeclient.vip`, `ZKM21.0.0`), Meteor, Wurst, LiquidBounce, and 25+ more —
see `Get-Help .\OceanSS.ps1 -Full` for the live list.

**Dual-use tooling is handled honestly:** Recaf, jadx, CFR, Procyon, vineflower, fernflower and
`jd-gui` are reverse-engineering tools, not cheats — they surface as **Info**, never as a Detection.

---

## 🔬 How detection works

Six independent phases, each feeding an evidence ledger:

1. **Hash & identify** — SHA-1 every jar in `%AppData%\.minecraft\mods`, batch-lookup Modrinth and CurseForge, with polite rate limiting and job-based parallelism.
2. **Deep content analysis** — unzip archives, compute Shannon entropy, parse Java class constant pools, decode fullwidth Unicode, detect obfuscator families.
3. **Execution forensics** — Prefetch timing, BAM/UserAssist launch records, ShimCache, MuiCache, NTFS USN delete records. Flags *"Executed & Deleted"*, *"Prefetch Deleted"* and `SYSTEM`-deny ACLs.
4. **Network & registry** — uninstall keys, the Teamspeak `tim` key, and `Get-DnsClientCache` for cheat domains resolved by this machine.
5. **Memory inspection** — optional, budgeted, read-only scan of `javaw.exe` / `explorer.exe` for unsigned DLLs sourced from `%Temp%`.
6. **JVM argument audit** — `-javaagent:`, `-Xbootclasspath/p:` and `-agentlib:jdwp` on the live Minecraft process.

### 📉 The false-positive doctrine

Every finding must survive **corroboration**:

```
Add-Finding ──▶ Register-ExecutionEvidence ──▶ Test-ExecutionCorrelation
                                                    │
                                          Resolve-FindingConfidence  ◀── demotion pass
                                                    │
                                              Get-Verdict  ──▶ needs ≥2 distinct sources
```

- Findings carry `-Confirmed` and `-Subject`; heuristic-only rows are **demoted** before scoring.
- A verdict of `CHEATING` requires multiple independent artefact families — never one weird file.
- Prefetch gaps are split into **core** vs **version-specific** baselines, and only escalate when
  ShimCache/BAM independently corroborate a deletion.
- Unverified hashes are an **Info**, not a warning — rebuilt or self-published jars legitimately
  won't match a repository.

---

## 🚀 Quick start

### Run from GitHub

```powershell
Invoke-RestMethod `
  https://raw.githubusercontent.com/amir-X1R/OpenOcean/main/OceanSS.ps1 `
  -OutFile .\OceanSS.ps1
