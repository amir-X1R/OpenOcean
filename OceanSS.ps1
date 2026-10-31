<#
.SYNOPSIS
    Ocean SS - Minecraft Screenshare Forensic Scanner + Local Ocean-styled Dashboard.

.DESCRIPTION
    Read-only forensic collection for Minecraft (Java) screenshares, rendered in a
    local web dashboard that mirrors the Ocean Anti-Cheat (anticheat.ac) results UI.

    The script NEVER writes to the registry, deletes files, terminates the subject's
    processes or touches protected processes. Every collector degrades gracefully
    when a capability is unavailable (missing elevation, locked ACL, offline API).

.PARAMETER Port
    Local dashboard port. Default 8080.

.PARAMETER MinecraftPath
    Extra Minecraft/lanucher directory to scan for jars. Optional.

.PARAMETER NoMemoryScan
    Skip the javaw.exe / explorer.exe memory scan.

.PARAMETER NoBrowser
    Do not auto-open the dashboard in the default browser.

.PARAMETER NoServer
    Collection only. Writes the report JSON and exits (used for validation / export).

.PARAMETER CurseForgeKey
    API key for the CurseForge fingerprint lookup. Falls back to
    $env:CURSEFORGE_API_KEY. Without a key only Modrinth performs verification.

.PARAMETER KeepAlive
    Hold the dashboard open until a key is pressed instead of auto-stopping.

.PARAMETER AutoShutdownSeconds
    Seconds the dashboard keeps serving after the scan completes. Default 25.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\OceanSS.ps1

.NOTES
    Detection logic inspired by x1r scanner & Ocean Anti-Cheat.
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [int]$Port = 8080,
    [string]$MinecraftPath,
    [switch]$NoMemoryScan,
    [switch]$NoBrowser,
    [switch]$NoServer,
    [switch]$NoElevate,
    [string]$ReportPath,
    # CurseForge fingerprint lookup needs an API key. Supply it here, or set
    # $env:CURSEFORGE_API_KEY. Without it Modrinth alone performs verification.
    [string]$CurseForgeKey,
    # Keep the dashboard up until a key is pressed instead of auto-stopping.
    [switch]$KeepAlive,
    # Seconds the dashboard keeps serving after the scan completes.
    [ValidateRange(5, 3600)][int]$AutoShutdownSeconds = 25
)

# ---------------------------------------------------------------------------
# -1. Self-elevation
#    Half of the forensic surface (BAM, USN journal, prefetch ACL, other-user
#    hives) is only readable from an elevated token, so the scanner re-launches
#    itself once and lets the original process exit. A failed prompt degrades to
#    a normal scan instead of blocking the screenshare.
# ---------------------------------------------------------------------------

$script:Elevated = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $script:Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch { $script:Elevated = $false }

if (-not $script:Elevated -and -not $NoElevate) {
    Write-Host ''
    Write-Host '  Ocean SS needs administrator rights for BAM, USN journal and prefetch.' -ForegroundColor Yellow
    Write-Host '  Requesting elevation...' -ForegroundColor DarkGray

    $hostExe = 'powershell.exe'
    try {
        $hostExe = (Get-Process -Id $PID -ErrorAction Stop).Path
        if (-not $hostExe) { $hostExe = 'powershell.exe' }
    }
    catch { $hostExe = 'powershell.exe' }

    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'))
    foreach ($name in $PSBoundParameters.Keys) {
        if ($name -eq 'NoElevate') { continue }
        $value = $PSBoundParameters[$name]
        if ($value -is [switch]) {
            if ($value.IsPresent) { $argList += "-$name" }
        }
        else {
            $argList += "-$name"
            $argList += ('"' + [string]$value + '"')
        }
    }

    try {
        Start-Process -FilePath $hostExe -ArgumentList $argList -Verb RunAs -ErrorAction Stop
        Write-Host '  Elevated instance started. This window can be closed.' -ForegroundColor DarkGray
        Write-Host ''
        exit 0
    }
    catch {
        Write-Host '  Elevation declined - continuing unelevated.' -ForegroundColor DarkGray
        Write-Host '  Some execution evidence (BAM, USN journal, prefetch) will be unavailable.' -ForegroundColor DarkGray
        Write-Host ''
    }
}

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'Continue'

# PowerShell 5.1 (.NET Framework 4.x) does not load the ZIP assemblies by default.
# Without this, [IO.Compression.ZipFile] never resolves and EVERY jar silently
# reports "archive unreadable" - which kills the whole Phase 2 jar pipeline.
foreach ($assembly in @('System.IO.Compression', 'System.IO.Compression.FileSystem')) {
    try { Add-Type -AssemblyName $assembly -ErrorAction Stop } catch { }
}
if (-not $ReportPath) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $ReportPath = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "ocean-ss-report-$stamp.json"
}

# ---------------------------------------------------------------------------
# 0. Configuration
# ---------------------------------------------------------------------------

$script:ToolVersion = '1.0.0'
$script:StartedAt   = Get-Date
$script:PIN         = -join (1..8 | ForEach-Object { 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'[(Get-Random -Maximum 34)] })

$script:Findings  = New-Object 'System.Collections.Generic.List[object]'
$script:Activity  = New-Object 'System.Collections.Generic.List[object]'
$script:Providers = New-Object 'System.Collections.Generic.List[object]'
$script:SeenKeys  = New-Object 'System.Collections.Generic.HashSet[string]'
$script:Whitelist = @{}          # sha1 -> "modrinth:project-slug"  (hash-verified => trusted)

# --- Evidence ledger ---------------------------------------------------------
# Every artefact that proves a file was RUN is registered here once, so later
# collectors can ask "was this actually executed, and was it inside the game
# session?" instead of merely "does it exist". This is what keeps a folder full
# of downloaded jars from producing a CHEATING verdict.
$script:ExecutionIndex   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:ExecutionRecords = New-Object 'System.Collections.Generic.List[object]'
$script:InstanceStart    = $null
$script:BootTime         = $null
$script:MemoryHits       = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:Downgraded       = 0

function Get-LeafName {
    <#
        [IO.Path]::GetFileName throws on registry/AppUserModelId values that
        contain quotes, pipes or control characters. Every path that comes from
        an artefact rather than the filesystem must go through this instead.
    #>
    param([string]$Path)
    if (-not $Path) { return '' }
    try {
        $leaf = [IO.Path]::GetFileName($Path)
        if ($leaf) { return $leaf }
    }
    catch { }
    $parts = @($Path -split '[\\/]')
    if ($parts.Count -gt 0 -and $parts[$parts.Count - 1]) { return $parts[$parts.Count - 1] }
    return $Path
}

function Register-ExecutionEvidence {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Nullable[datetime]]$Time,
        [Parameter(Mandatory)][string]$Source
    )
    if (-not $Path) { return }
    $leaf = Get-LeafName $Path
    if (-not $leaf) { $leaf = $Path }
    [void]$script:ExecutionIndex.Add($leaf.ToLowerInvariant())
    $script:ExecutionRecords.Add([pscustomobject]@{
            leaf  = $leaf.ToLowerInvariant()
            path  = $Path
            time  = $Time
            source = $Source
        })
}

function Test-ExecutionCorrelation {
    <#
        Returns @{ executed = bool; inInstance = bool; source = ''; time = '' }.
        'executed'   - the artefact is known to have run on this machine.
        'inInstance' - it ran at/after the Minecraft instance start (the only
                       state that justifies a Detection rather than a Warning).
    #>
    param([Parameter(Mandatory)][string]$PathOrName)

    $leaf = Get-LeafName $PathOrName
    if (-not $leaf) { $leaf = $PathOrName }
    $key = $leaf.ToLowerInvariant()

    $result = @{ executed = $false; inInstance = $false; source = ''; time = '' }
    if (-not $script:ExecutionIndex.Contains($key)) { return $result }

    $result.executed = $true
    foreach ($rec in $script:ExecutionRecords) {
        if ($rec.leaf -ne $key) { continue }
        if ($result.source -eq '' ) { $result.source = $rec.source }
        if ($null -eq $rec.time) { continue }
        $result.time = ConvertTo-IsoTime $rec.time
        if ($script:InstanceStart -and ([datetime]$rec.time) -ge $script:InstanceStart.AddMinutes(-2)) {
            $result.inInstance = $true
        }
        if ($script:BootTime -and ([datetime]$rec.time) -ge $script:BootTime) {
            if (-not $result.source) { $result.source = $rec.source }
        }
    }
    return $result
}

function Test-JarExecution {
    <#
        PRIMARY DIRECTIVE: a jar is only a Detection when it was actually LOADED
        into the running instance. Membership of the live instance's mods folder
        (present before launch) is how Minecraft proves loading; otherwise we
        require an execution artefact or a resident signature in javaw memory.
    #>
    param($Jar)

    $state = @{ executed = $false; inInstance = $false; reason = '' }
    if ($null -eq $Jar) { return $state }

    $path = [string]$Jar.path
    $inGameDir = $path -match '(?i)\\(mods|versions|gameDir)\\' -or $path -match '(?i)\\\.minecraft\\'

    $corr = Test-ExecutionCorrelation -PathOrName $path
    if ($corr.executed) {
        $state.executed = $true
        $state.inInstance = [bool]$corr.inInstance
        $state.reason = "execution artefact: $($corr.source)"
        if ($corr.time) { $state.reason += " at $($corr.time)" }
    }

    if (-not $state.inInstance -and $inGameDir -and $script:InstanceStart) {
        $modified = $null
        try { if ($Jar.modified) { $modified = [datetime]$Jar.modified } } catch { }
        if ($null -ne $modified -and $modified -le $script:InstanceStart.AddMinutes(2)) {
            $state.executed = $true
            $state.inInstance = $true
            $state.reason = "present in the running instance's mod folder before launch"
        }
    }

    if (-not $state.inInstance -and @($Jar.signatures).Count -gt 0) {
        foreach ($sig in @($Jar.signatures)) {
            if ($script:MemoryHits.Contains([string]$sig)) {
                $state.executed = $true
                $state.inInstance = $true
                $state.reason = "'$sig' is resident in javaw.exe memory"
                break
            }
        }
    }

    return $state
}

# ---------------------------------------------------------------------------
# Detection target registry - 3 tiers.
#
# False positives are controlled by MATCHING CONTEXT, not by having fewer
# targets. A brand name is only safe where the surrounding text already proves
# what it is:
#
#   CheatStrings : package paths, domains and distinctive class names. Used by
#                  the LIVE MEMORY scan and the jar CONTENT scan, where a hit
#                  is proof on its own. Never contains a bare English word.
#   JarTokens    : brand tokens matched against jar entry names / manifests,
#                  where "inside a mod archive" is already strong context.
#   CheatTokens  : brand tokens matched against file names, registry values,
#                  USN records, PowerShell history and prefetch names.
#
# Single generic words ('smoke', 'stringer', 'future', 'flux', 'rise') never
# reach the memory scan - they only appear in JarTokens/CheatTokens where the
# context disambiguates them.
# ---------------------------------------------------------------------------

# Tier 1 - high specificity (memory + jar contents). 100+ entries.
$script:CheatStrings = @(
    # --- Jar clients: package paths / dotted packages --------------------
    'net/ccbluex/liquidbounce', 'net.ccbluex.liquidbounce',
    'meteordevelopment/meteorclient', 'meteordevelopment.meteorclient',
    'net/wurstclient', 'net.wurstclient',
    'org/rusherhack', 'rusherhack.org',
    'net/futureclient', 'net.futureclient',
    'com/astolfo', 'astolfo.dev', 'AstolfoClient',
    'cc/novoline', 'cc.novoline', 'NovolineClient',
    'dev/pandaware', 'dev.pandaware', 'pandaware.cc',
    'client/konas', 'konasclient', 'konas.cc',
    'kami/blue', 'kamiblue', 'wtf/kamiblue',
    'salhack', 'salhack.cc', 'SalHackClient',
    'gamesense.pub', 'gamesenseclient', 'com/gamesense',
    'bleachhack', 'bleachhackclient', 'org/bleachhack',
    'thunderhack', 'thunderhackreleazed', 'com/thunderhack',
    'forgehax', 'com/forgehax',
    'wolframclient', 'wtf/wolfram',
    'aristois', 'me/aristois',
    'mathax', 'me/mathax',
    'phobosclient', 'org/phobos', 'phobos-v2',
    'tenacityclient', 'click/thunder',
    'riseclient', 'com/rise', 'rise.client',
    'aobaclient', 'me/aoba',
    'eulenclient', 'fun/eulen',
    'moonlightclient', 'net/moonlight',
    'donutclient', 'dev/donut',
    'xenonclient', 'net/xenon',
    'hellionclient', 'fun/hellion',
    'argonclient', 'wtf/argon',
    'asteriaclient', 'fun/asteria',
    'intentclient', 'me/intent',
    'fluxclient', 'fun/flux',
    'sigmaclient', 'sigma.client',
    'impactclient', 'me/impact',
    'jigsawclient', 'fun/jigsaw',
    'zeroeightysix', 'me/zeroeightysix',
    'com/zenith', 'net/zenith',
    'orchardclient', 'Orchard client', 'orchard-client',
    # --- Standalone clients / injected natives ---------------------------
    'PrestigeClient', 'prestigeclient.vip', 'prestige-client', 'ZKM21.0.0',
    'Vape421Native', 'VapeClient', 'vape.gg', 'Vape Lite', 'Vape-v4',
    'x1rclient', 'x1r.client',
    # --- Auth / loader services ------------------------------------------
    'keyauth.win', 'keyauth.cc', 'KeyauthApp', 'key-auth',
    # --- Obfuscators (domain / distinctive form only) ---------------------
    'skidfuscator.com', 'skidfuscator', 'io/github/skidfuscator',
    'bozar.best', 'bozar',
    'branchlock', 'binscure', 'qprotect', 'qProtect',
    'zelix.klaas', 'zelixklaas', 'com/zelix',
    'scuti.obf', 'org/scuti',
    'jnic.obf', 'net/oneeighthree/jnic',
    'caesium.obf', 'com/caesium',
    'radon.obf', 'xyz/radon',
    # --- Injection / bypass markers ---------------------------------------
    'ImportCode', 'Boot instance', 'VirtualDisk bypass', 'Fun Loader',
    'GetDpiForWindow(IntPtr', 'CommandInvocation(Add-Type)'
)

# Tier 2 - jar entry names / manifest text. Context: inside a mod archive.
$script:JarTokens = @(
    # client packages
    'net/ccbluex/liquidbounce', 'meteordevelopment/meteorclient', 'net/wurstclient',
    'org/rusherhack', 'net/futureclient', 'com/astolfo', 'cc/novoline',
    'dev/pandaware', 'client/konas', 'kami/blue', 'salhack', 'gamesense',
    'bleachhack', 'thunderhack', 'forgehax', 'wolfram', 'aristois', 'mathax',
    'phobos', 'tenacity', 'rise', 'aoba', 'eulen', 'moonlightclient', 'donut',
    'xenon', 'hellion', 'argon', 'asteria', 'intent', 'flux', 'sigma', 'impact',
    'jigsaw', 'huzuni', 'salhack', 'meteor', 'wurst', 'liquidbounce', 'novoline',
    'pandaware', 'astolfo', 'rusherhack', 'orchard', 'prestige', 'vape',
    # obfuscator markers (only meaningful inside a jar)
    'skidfuscator', 'radon', 'caesium', 'bozar', 'branchlock', 'binscure',
    'qprotect', 'qprotect.jar', 'zelix', 'stringer', 'jnic', 'scuti',
    'allatori', 'dashO', 'proguard', 'guardvm', 'zkm',
    # loader / bypass markers
    'funloader', 'fun loader', 'bypass', 'injector', 'recaf', 'bytecode-agent'
)

# Tier 3 - file names, registry values, USN rows, prefetch, shell history.
$script:CheatTokens = @(
    'vape', 'vape-v4', 'vapeclient', 'prestigeclient', 'prestige client',
    'prestige-client', 'liquidbounce', 'wurstclient', 'meteorclient',
    'rusherhack', 'astolfo', 'skidfuscator', 'bozar', 'keyauth',
    'orchard client', 'orchardclient', 'orchard.jar', 'konasclient',
    'gamesense', 'tenacity client', 'tenacityclient', 'riseclient',
    'novoline', 'pandaware', 'futureclient', 'salhack', 'bleachhack',
    'thunderhack', 'forgehax', 'wolframclient', 'mathax', 'phobosclient',
    'eulenclient', 'aobaclient', 'moonlightclient', 'donutclient',
    'xenonclient', 'hellionclient', 'argonclient', 'asteriaclient',
    'intentclient', 'fluxclient', 'sigmaclient', 'impactclient',
    'jigsawclient', 'huzuni', 'kamiblue', 'aristois', 'x1rclient',
    'clarity-cracked', 'goobacracked', 'echo-client', 'crackedby'
)

$script:CheatDomains = @(
    'vape.gg', 'prestigeclient.vip', 'liquidbounce.net', 'liquidbounce.cc',
    'wurstclient.net', 'meteorclient.com', 'rusherhack.org', 'astolfo.dev',
    'keyauth.win', 'keyauth.cc', 'skidfuscator.com', 'bozar.best',
    'konasclient.com', 'konas.cc', 'novoline.cc', 'pandaware.cc',
    'salhack.cc', 'gamesense.pub', 'thunderhack.cc', 'futureclient.net',
    'bleachhack.org', 'forgehax.com', 'wolframclient.com', 'aristois.gg',
    'aobaclient.com', 'eulen.xyz', 'riseclient.xyz', 'tenacity.dev',
    'fluxclient.cc', 'sigmaclient.net', 'impactclient.net', 'huzuni.net',
    'x1r.dev', 'x1rclient.com', 'orbitclient.net', 'aristois.net'
)

# Client package signatures looked for inside jar entry names. Ordered so the
# most specific path wins; the value is what the report shows.
$script:JarSignatures = [ordered]@{
    'net/ccbluex/liquidbounce'       = 'LiquidBounce'
    'net/ccbluex/liquidbounce/event' = 'LiquidBounce'
    'meteordevelopment/meteorclient' = 'Meteor'
    'net/wurstclient'                = 'Wurst'
    'org/rusherhack'                 = 'RusherHack'
    'net/futureclient'               = 'Future'
    'com/astolfo'                    = 'Astolfo'
    'cc/novoline'                    = 'Novoline'
    'dev/pandaware'                  = 'Pandaware'
    'client/konas'                   = 'Konas'
    'kami/blue'                      = 'KAMI Blue'
    'salhack'                        = 'SalHack'
    'gamesense'                      = 'GameSense'
    'bleachhack'                     = 'BleachHack'
    'thunderhack'                    = 'ThunderHack'
    'forgehax'                       = 'ForgeHax'
    'wolfram'                        = 'Wolfram'
    'aristois'                       = 'Aristois'
    'mathax'                         = 'MatHax'
    'phobos'                         = 'Phobos'
    'tenacity'                       = 'Tenacity'
    'rise'                           = 'Rise'
    'aoba'                           = 'Aoba'
    'eulen'                          = 'Eulen'
    'moonlightclient'                = 'MoonLight'
    'donutclient'                    = 'Donut'
    'xenonclient'                    = 'Xenon'
    'hellionclient'                  = 'Hellion'
    'argonclient'                    = 'Argon'
    'asteriaclient'                  = 'Asteria'
    'intentclient'                   = 'Intent'
    'fluxclient'                     = 'Flux'
    'sigmaclient'                    = 'Sigma'
    'impactclient'                   = 'Impact'
    'jigsawclient'                   = 'Jigsaw'
    'huzuni'                         = 'Huzuni'
    'zeroeightysix'                  = 'ZeroEightSix'
    'com/zenith'                     = 'Zenith'
    'orchard'                        = 'Orchard'
    'prestige'                       = 'Prestige'
    'vape'                           = 'Vape'
    'x1rclient'                      = 'x1r Client'
    'skidfuscator'                   = 'Skidfuscator'
}

$script:ObfuscatorTokens = @(
    'skidfuscator', 'radon', 'caesium', 'bozar', 'branchlock', 'binscure',
    'qprotect', 'zelix', 'stringer', 'jnic', 'scuti', 'smoke', 'zkm'
)

# Process names are only useful for the standalone executables (Vape, Prestige).
# Jar-based clients never appear here, and debuggers are flagged as dual-use.
$script:CheatProcesses = @(
    'Vape', 'VapeClient', 'Vape-v4', 'Prestige', 'PrestigeClient', 'Orchard',
    'Bozar', 'Skidfuscator', 'Keyauth', 'LiquidBounce', 'Meteor', 'Wurst',
    'RusherHack', 'Astolfo', 'Novoline', 'SalHack', 'Konas', 'GameSense',
    'BleachHack', 'ThunderHack', 'ForgeHax', 'Aristois', 'Tenacity', 'Rise',
    'Eulen', 'Sigma', 'Impact', 'Huzuni', 'x1r', 'FunLoader', 'Bypass'
)
$script:DualUseProcesses = @(
    'CheatEngine', 'x64dbg', 'ProcessHacker', 'HTTPDebuggerUI', 'Recaf',
    'JD-GUI', 'JavaDecompiler', 'Frida', 'ollydbg', 'WinDbg', 'dnSpy'
)

# Vendor signature allowlist. Unsigned-from-a-known-publisher is NOT evidence;
# only mappings from hostile directories are. This single list removes the
# largest source of false positives in the native-module check.
$script:TrustedSigners = @(
    'Microsoft', 'Windows', 'NVIDIA', 'Intel Corporation', 'AMD', 'Advanced Micro Devices',
    'Realtek', 'Oracle', 'Amazon', 'Amazon.com', 'LWJGL', 'Gluon', 'JetBrains',
    'Mojang', 'Eclipse Foundation', 'The Eclipse Foundation', 'Dell', 'HP', 'Lenovo',
    'ASUSTeK', 'Acer', 'TOSHIBA', 'SAMSUNG', 'Synaptics', 'Logitech', 'SteelSeries',
    'Corsair', 'Razer', 'Broadcom', 'Qualcomm', 'MediaTek', 'Apple', 'Adobe',
    'Google', 'Mozilla', 'Opera Software', 'Discord', 'Valve', 'Steam', 'Notepad++',
    'Node.js', 'Docker', 'Git', 'Python Software Foundation', 'The Python Software Foundation'
)

# Reverse-engineering utilities legitimately mention obfuscator names in their
# entry lists (Recaf ships ZKM/ProGuard presets). Their presence is dual-use
# context, never evidence of a client, so they get their own quiet finding.
$script:DualUseJars = @(
    'recaf', 'jd-gui', 'jadx', 'cfr', 'procyon', 'vineflower', 'fernflower',
    'bytecode-viewer', 'krakatau', 'enigma', 'minecraft-decompiler'
)

# Prefetch baselines are split because "file not in the Prefetch folder" only
# means "deleted" when the record should certainly exist:
#   core    - processes every healthy Windows install runs constantly. Missing
#             several of these is a real signal.
#   extend  - version/hardware dependent (SEARCHAPP is Win10-only, USEROBE only
#             runs during OOBE, WUDFHOST only with UMDF devices). Their absence
#             is normal on modern Windows and is reported as context only.
$script:BaselinePrefetch = @(
    'EXPLORER.EXE', 'SVCHOST.EXE', 'TASKHOSTW.EXE', 'CONHOST.EXE',
    'DLLHOST.EXE', 'RUNDLL32.EXE', 'SIHOST.EXE'
)
$script:BaselinePrefetchOptional = @(
    'BACKGROUNDTASKHOST.EXE', 'SEARCHAPP.EXE', 'SHTASKHOSTW.EXE',
    'USEROBE.EXE', 'WUDFHOST.EXE', 'SEARCHHOST.EXE'
)
$script:PrefetchMissingCore = @()
$script:PrefetchRecordTotal  = 0

# Friendly-name lookup used by every collector that reports a raw needle.
$script:CheatNameMap = @{
    'liquidbounce' = 'LiquidBounce'; 'ccbluex' = 'LiquidBounce'
    'meteor' = 'Meteor'; 'wurst' = 'Wurst'; 'rusherhack' = 'RusherHack'
    'futureclient' = 'Future'; 'astolfo' = 'Astolfo'; 'novoline' = 'Novoline'
    'pandaware' = 'Pandaware'; 'konas' = 'Konas'; 'kamiblue' = 'KAMI Blue'
    'salhack' = 'SalHack'; 'gamesense' = 'GameSense'; 'bleachhack' = 'BleachHack'
    'thunderhack' = 'ThunderHack'; 'forgehax' = 'ForgeHax'; 'wolfram' = 'Wolfram'
    'aristois' = 'Aristois'; 'mathax' = 'MatHax'; 'phobos' = 'Phobos'
    'tenacity' = 'Tenacity'; 'rise' = 'Rise'; 'aoba' = 'Aoba'; 'eulen' = 'Eulen'
    'moonlight' = 'MoonLight'; 'donut' = 'Donut'; 'xenon' = 'Xenon'
    'hellion' = 'Hellion'; 'argon' = 'Argon'; 'asteria' = 'Asteria'
    'intent' = 'Intent'; 'flux' = 'Flux'; 'sigma' = 'Sigma'; 'impact' = 'Impact'
    'jigsaw' = 'Jigsaw'; 'huzuni' = 'Huzuni'; 'zeroeightysix' = 'ZeroEightSix'
    'zenith' = 'Zenith'; 'orchard' = 'Orchard'; 'prestige' = 'Prestige'
    'vape' = 'Vape V4'; 'x1r' = 'x1r Client'; 'keyauth' = 'KeyAuth'
    'skidfuscator' = 'Skidfuscator'; 'radon' = 'Radon'; 'caesium' = 'Caesium'
    'bozar' = 'Bozar'; 'branchlock' = 'Branchlock'; 'binscure' = 'Binscure'
    'qprotect' = 'qProtect'; 'zelix' = 'Zelix'; 'stringer' = 'Stringer'
    'jnic' = 'JNIC'; 'scuti' = 'Scuti'; 'smoke' = 'Smoke'; 'zkm' = 'ZKM'
    'javaagent' = 'JVM Agent'; 'bootclasspath' = 'JVM Agent'
}

# Read-only interop. PROCESS_VM_READ only, plus QUERY_INFORMATION to walk VADs.
$script:MemScanSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class OceanMemScan
{
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint MEM_COMMIT                = 0x1000;
    private const uint PAGE_NOACCESS             = 0x01;
    private const uint PAGE_GUARD                = 0x100;
    private const uint PAGE_READONLY             = 0x02;
    private const uint PAGE_READWRITE            = 0x04;
    private const uint PAGE_WRITECOPY            = 0x08;
    private const uint PAGE_EXECUTE_READ         = 0x20;
    private const uint PAGE_EXECUTE_READWRITE    = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY    = 0x80;

    // First-byte indexes keep the hot loop at native speed: every byte is compared
    // once against a lookup table instead of running N full string searches over
    // multi-gigabyte heaps.
    private static int[][] asciiFirst;
    private static int[][] wideFirst;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

    public static string[] Scan(int pid, string[] needles, long maxTotalBytes, long maxRegionBytes, int timeoutMs)
    {
        List<string> output = new List<string>();
        Dictionary<string, int> hits = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        IntPtr h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (h == IntPtr.Zero)
        {
            output.Add("!ERROR\t" + Marshal.GetLastWin32Error().ToString());
            return output.ToArray();
        }

        long totalRead = 0;
        bool timedOut = false;
        int started = Environment.TickCount;
        byte[] buffer = new byte[2 * 1024 * 1024];
        int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
        BuildIndex(needles);

        try
        {
            IntPtr addr = IntPtr.Zero;
            while (true)
            {
                if (unchecked(Environment.TickCount - started) > timeoutMs) { timedOut = true; break; }

                long cursor = addr.ToInt64();
                if (cursor < 0) break;
                if (cursor > 0x7FFFFFFEFFFFL) break;

                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(h, new IntPtr(cursor), out mbi, new IntPtr(mbiSize)) == IntPtr.Zero) break;

                long regionBase = mbi.BaseAddress.ToInt64();
                long regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;

                long next = regionBase + regionSize;
                if (next <= cursor) break;

                uint p = mbi.Protect;
                bool readable = (p & PAGE_NOACCESS) == 0 && (p & PAGE_GUARD) == 0 &&
                    ((p & PAGE_READONLY) != 0 || (p & PAGE_READWRITE) != 0 || (p & PAGE_WRITECOPY) != 0 ||
                     (p & PAGE_EXECUTE_READ) != 0 || (p & PAGE_EXECUTE_READWRITE) != 0 || (p & PAGE_EXECUTE_WRITECOPY) != 0);

                if (mbi.State == MEM_COMMIT && readable && regionSize <= maxRegionBytes && totalRead < maxTotalBytes)
                {
                    long offset = 0;
                    while (offset < regionSize)
                    {
                        if (unchecked(Environment.TickCount - started) > timeoutMs) { timedOut = true; break; }

                        int want = (int)Math.Min((long)buffer.Length, regionSize - offset);
                        IntPtr gotPtr;
                        if (!ReadProcessMemory(h, new IntPtr(regionBase + offset), buffer, new IntPtr(want), out gotPtr)) break;

                        int got = (int)gotPtr;
                        if (got > 0)
                        {
                            totalRead += got;
                            ScanBufferFast(buffer, got, needles, hits);
                        }
                        offset += (got > 0) ? got : want;
                        if (totalRead >= maxTotalBytes) break;
                    }
                }

                addr = new IntPtr(next);
                if (timedOut) break;
            }
        }
        finally
        {
            CloseHandle(h);
        }

        output.Add("!STATS\t" + totalRead.ToString() + "\t" + needles.Length.ToString());
        foreach (KeyValuePair<string, int> kv in hits)
        {
            output.Add(kv.Key + "\t" + kv.Value.ToString());
        }
        if (timedOut) output.Add("!TIMEOUT");
        else output.Add("!DONE");
        return output.ToArray();
    }

    private static void BuildIndex(string[] needles)
    {
        List<int>[] ascii = new List<int>[256];
        List<int>[] wide = new List<int>[256];

        for (int i = 0; i < needles.Length; i++)
        {
            string n = needles[i];
            if (string.IsNullOrEmpty(n)) { continue; }
            byte b = (byte)(n[0] & 0xFF);
            if (ascii[b] == null) { ascii[b] = new List<int>(); }
            ascii[b].Add(i);
            if (n[0] < 128)
            {
                if (wide[b] == null) { wide[b] = new List<int>(); }
                wide[b].Add(i);
            }
        }

        asciiFirst = new int[256][];
        wideFirst = new int[256][];
        for (int i = 0; i < 256; i++)
        {
            if (ascii[i] != null) { asciiFirst[i] = ascii[i].ToArray(); }
            if (wide[i] != null) { wideFirst[i] = wide[i].ToArray(); }
        }
    }

    private static void ScanBufferFast(byte[] buf, int length, string[] needles, Dictionary<string, int> hits)
    {
        for (int i = 0; i < length; i++)
        {
            int[] cand = asciiFirst[buf[i]];
            if (cand != null)
            {
                for (int k = 0; k < cand.Length; k++)
                {
                    if (MatchAscii(buf, i, length, needles[cand[k]])) { Record(hits, needles[cand[k]]); }
                }
            }

            if (i + 1 < length && buf[i + 1] == 0)
            {
                cand = wideFirst[buf[i]];
                if (cand != null)
                {
                    for (int k = 0; k < cand.Length; k++)
                    {
                        if (MatchWide(buf, i, length, needles[cand[k]])) { Record(hits, needles[cand[k]]); }
                    }
                }
            }
        }
    }

    private static bool MatchAscii(byte[] buf, int offset, int length, string needle)
    {
        if (offset + needle.Length > length) { return false; }
        for (int j = 0; j < needle.Length; j++)
        {
            int a = buf[offset + j];
            if (a >= 65 && a <= 90) { a += 32; }
            int b = needle[j];
            if (b >= 65 && b <= 90) { b += 32; }
            if (a != b) { return false; }
        }
        return true;
    }

    private static bool MatchWide(byte[] buf, int offset, int length, string needle)
    {
        if (offset + (needle.Length * 2) > length) { return false; }
        for (int j = 0; j < needle.Length; j++)
        {
            int z = buf[offset + (j * 2) + 1];
            if (z != 0) { return false; }
            int a = buf[offset + (j * 2)];
            if (a >= 65 && a <= 90) { a += 32; }
            int b = needle[j];
            if (b >= 65 && b <= 90) { b += 32; }
            if (a != b) { return false; }
        }
        return true;
    }

    private static void Record(Dictionary<string, int> hits, string needle)
    {
        int c;
        hits.TryGetValue(needle, out c);
        hits[needle] = c + 1;
    }
}
'@

try {
    if (-not ('OceanMemScan' -as [type])) {
        Add-Type -TypeDefinition $script:MemScanSource -Language CSharp -ErrorAction Stop
    }
}
catch {
    Write-Verbose "Memory scan interop unavailable: $($_.Exception.Message)"
}

# Jar string extraction + desktop window enumeration (Bypass Fun Loader).
$script:ExtraSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class OceanStrings
{
    private static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

    public static string[] Extract(byte[] data, int length, int minLen, int maxCount)
    {
        List<string> found = new List<string>();
        if (data == null || length <= 0) { return found.ToArray(); }

        int start = -1;
        for (int i = 0; i < length; i++)
        {
            byte b = data[i];
            if (b >= 32 && b <= 126)
            {
                if (start < 0) { start = i; }
            }
            else
            {
                if (start >= 0 && (i - start) >= minLen)
                {
                    found.Add(Latin1.GetString(data, start, i - start));
                    if (found.Count >= maxCount) { return found.ToArray(); }
                }
                start = -1;
            }
        }
        if (start >= 0 && (length - start) >= minLen && found.Count < maxCount)
        {
            found.Add(Latin1.GetString(data, start, length - start));
        }

        start = -1;
        for (int i = 0; i + 1 < length; i += 2)
        {
            if (data[i] >= 32 && data[i] <= 126 && data[i + 1] == 0)
            {
                if (start < 0) { start = i; }
            }
            else
            {
                if (start >= 0 && ((i - start) / 2) >= minLen)
                {
                    found.Add(Encoding.Unicode.GetString(data, start, i - start));
                    if (found.Count >= maxCount) { return found.ToArray(); }
                }
                start = -1;
            }
        }
        return found.ToArray();
    }
}

public static class OceanWindows
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MONITORINFOEX
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string szDevice;
    }

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFOEX lpmi);

    public static string[] List()
    {
        List<string> rows = new List<string>();
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam)
        {
            try
            {
                if (!IsWindowVisible(hWnd)) { return true; }
                StringBuilder sb = new StringBuilder(512);
                GetWindowText(hWnd, sb, sb.Capacity);
                string title = sb.ToString();
                if (string.IsNullOrEmpty(title)) { return true; }

                uint pid;
                GetWindowThreadProcessId(hWnd, out pid);
                if (pid == 0) { return true; }

                string device = "";
                IntPtr mon = MonitorFromWindow(hWnd, 2);
                if (mon != IntPtr.Zero)
                {
                    MONITORINFOEX mi = new MONITORINFOEX();
                    mi.cbSize = Marshal.SizeOf(typeof(MONITORINFOEX));
                    if (GetMonitorInfo(mon, ref mi)) { device = mi.szDevice ?? ""; }
                }

                rows.Add(pid.ToString() + "\t" + device + "\t" + title.Replace("\t", " "));
            }
            catch { }
            return true;
        }, IntPtr.Zero);
        return rows.ToArray();
    }
}
'@

try {
    if (-not ('OceanStrings' -as [type])) {
        Add-Type -TypeDefinition $script:ExtraSource -Language CSharp -ErrorAction Stop
    }
}
catch {
    Write-Verbose "Jar/window interop unavailable: $($_.Exception.Message)"
}

# Java class-file constant-pool reader + AppCompatCache (ShimCache) reader.
# Raw byte scans miss strings that an obfuscator split or built at runtime; the
# constant pool is where javac actually stores them, so reading it directly is
# both cheaper and far harder to evade.
$script:AnalysisSource = @'
using System;
using System.Collections.Generic;
using System.Text;

public static class OceanClassFile
{
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, false);

    // Walks the constant pool exactly as javac wrote it and returns every
    // CONSTANT_Utf8 entry of at least minLen characters.
    public static string[] ExtractUtf8(byte[] b, int minLen, int maxCount)
    {
        List<string> outp = new List<string>();
        if (b == null || b.Length < 10) { return outp.ToArray(); }
        if (b[0] != 0xCA || b[1] != 0xFE || b[2] != 0xBA || b[3] != 0xBE) { return outp.ToArray(); }

        int cpCount = ((b[8] & 0xFF) << 8) | (b[9] & 0xFF);
        if (cpCount < 2 || cpCount > 8192) { return outp.ToArray(); }

        int p = 10;
        for (int i = 1; i < cpCount; i++)
        {
            if (p >= b.Length) { break; }
            int tag = b[p++] & 0xFF;
            switch (tag)
            {
                case 1: // CONSTANT_Utf8 - the only place class text lives
                    if (p + 2 > b.Length) { p = b.Length; break; }
                    int len = ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
                    p += 2;
                    if (p + len > b.Length) { p = b.Length; break; }
                    if (len >= minLen)
                    {
                        string s = Decode(b, p, len);
                        if (s.Length >= minLen)
                        {
                            outp.Add(s);
                            if (outp.Count >= maxCount) { return outp.ToArray(); }
                        }
                    }
                    p += len;
                    break;
                case 3: case 4: p += 4; break;
                case 5: case 6: p += 8; i++; break;       // long / double take 2 slots
                case 7: case 8: case 16: case 19: case 20: p += 2; break;
                case 9: case 10: case 11: case 12: case 17: case 18: p += 4; break;
                case 15: p += 3; break;
                default:
                    // Unknown tag - stop rather than desynchronise the stream.
                    return outp.ToArray();
            }
        }
        return outp.ToArray();
    }

    // Modified UTF-8: NUL is encoded as C0 80 and must be recovered or every
    // subsequent comparison against a needle drifts by one byte.
    private static string Decode(byte[] b, int off, int len)
    {
        byte[] tmp = new byte[len];
        int n = 0;
        for (int i = 0; i < len; i++)
        {
            if (b[off + i] == 0xC0 && i + 1 < len && b[off + i + 1] == 0x80) { tmp[n++] = 0x00; i++; }
            else { tmp[n++] = b[off + i]; }
        }
        try { return StrictUtf8.GetString(tmp, 0, n); }
        catch { return Encoding.GetEncoding(28591).GetString(tmp, 0, n); }
    }
}

public static class OceanShimCache
{
    // AppCompatCache stores image paths as UTF-16LE but with an undocumented
    // header that changes between Windows builds, so instead of guessing the
    // offset table we read printable UTF-16 runs at both alignments and keep
    // only real image paths.
    public static string[] ExtractPaths(byte[] data, int minLen, int maxCount)
    {
        List<string> res = new List<string>();
        if (data == null || data.Length < 16) { return res.ToArray(); }

        for (int align = 0; align < 2; align++)
        {
            int runStart = -1;
            for (int i = align; i + 1 < data.Length; i += 2)
            {
                int c = data[i] | (data[i + 1] << 8);
                bool printable = (c >= 0x20 && c < 0x7F);
                if (printable)
                {
                    if (runStart < 0) { runStart = i; }
                }
                else if (runStart >= 0)
                {
                    Consider(data, runStart, i, minLen, res, maxCount);
                    runStart = -1;
                    if (res.Count >= maxCount) { return res.ToArray(); }
                }
            }
            if (runStart >= 0) { Consider(data, runStart, data.Length - ((data.Length - runStart) % 2), minLen, res, maxCount); }
        }
        return res.ToArray();
    }

    private static void Consider(byte[] data, int start, int end, int minLen, List<string> res, int maxCount)
    {
        int chars = (end - start) / 2;
        if (chars < minLen) { return; }

        StringBuilder sb = new StringBuilder(chars);
        for (int i = 0; i < chars; i++) { sb.Append((char)(data[start + (i * 2)] | (data[start + (i * 2) + 1] << 8))); }
        string s = sb.ToString();

        if (s.IndexOf('\\') < 0) { return; }
        string low = s.ToLowerInvariant();
        if (!low.EndsWith(".exe") && !low.EndsWith(".dll") && !low.EndsWith(".sys") && !low.EndsWith(".bat")) { return; }
        if (!res.Contains(s)) { res.Add(s); }
    }
}
'@

try {
    if (-not ('OceanClassFile' -as [type])) {
        Add-Type -TypeDefinition $script:AnalysisSource -Language CSharp -ErrorAction Stop
    }
}
catch {
    Write-Verbose "Class-file/ShimCache interop unavailable: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# 1. Shared helpers
# ---------------------------------------------------------------------------

function Write-Phase {
    param(
        [string]$Activity,
        [int]$Percent,
        [string]$Status = ''
    )
    $p = [Math]::Max(0, [Math]::Min(100, $Percent))
    Write-Progress -Id 1 -Activity 'Ocean SS - screenshare scan' -Status $Activity `
        -PercentComplete $p -CurrentOperation $Status
}

function Add-Finding {
    param(
        [string]$Category = 'Overview',
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail = '',
        [ValidateSet('Detection', 'Warning', 'Legit', 'Info')][string]$Severity = 'Warning',
        [string[]]$Tags = @(),
        [string]$Time = '',
        [double]$Score = -1,
        # -Confirmed marks evidence that cannot be explained innocently (a live
        # cheat process, a resident client string, a cheat-only registry marker).
        # Anything else is a heuristic and is subject to corroboration review.
        [switch]$Confirmed,
        # -Subject is the thing being accused. Two findings that share a subject
        # corroborate each other; an uncorroborated heuristic cannot be a
        # Detection after Resolve-FindingConfidence runs.
        [string]$Subject = ''
    )

    $key = "$Category|$Title"
    if (-not $script:SeenKeys.Add($key)) { return }

    $tagList = New-Object 'System.Collections.Generic.List[string]'
    foreach ($t in $Tags) { if ($t -and -not $tagList.Contains($t)) { $tagList.Add($t) } }
    if ($Severity -eq 'Detection' -and -not $tagList.Contains('Detection')) { $tagList.Add('Detection') }
    if ($Severity -eq 'Warning' -and -not $tagList.Contains('Warning')) { $tagList.Add('Warning') }

    $script:Findings.Add([pscustomobject]@{
        id        = "f$($script:Findings.Count + 1)"
        category  = $Category
        title     = $Title
        detail    = $Detail
        severity  = $Severity
        tags      = $tagList.ToArray()
        time      = $Time
        score     = $Score
        confirmed = [bool]$Confirmed
        subject   = $(if ($Subject) { $Subject.ToLowerInvariant() } else { $Title.ToLowerInvariant() })
    })
}

function Resolve-PrefetchTamper {
    <#
        Cross-artefact reconciliation for the prefetch baseline gap warning.

        "SEARCHAPP.EXE has no .pf file" is normal on Windows 11. "SEARCHAPP.EXE
        has no .pf file, yet AppCompatCache and MuiCache both record it running"
        means the record was removed after the fact. Only the second shape is a
        Detection, and it needs at least two missing core records to get there.
    #>
    $missing = @($script:PrefetchMissingCore)
    if ($missing.Count -lt 2) { return }

    $seen = New-Object 'System.Collections.Generic.List[string]'
    $source = ''
    foreach ($m in $missing) {
        $c = Test-ExecutionCorrelation -PathOrName $m
        if ($c.executed) {
            $seen.Add($m)
            if (-not $source) { $source = [string]$c.source }
        }
    }
    if ($seen.Count -lt 1) { return }

    foreach ($f in $script:Findings) {
        if ($f.title -ne 'Prefetch Baseline Gaps') { continue }

        $tags = New-Object 'System.Collections.Generic.List[string]'
        foreach ($t in $f.tags) { if ($t -ne 'Warning') { $tags.Add($t) } }
        if (-not $tags.Contains('Detection')) { $tags.Add('Detection') }

        $f.severity  = 'Detection'
        $f.confirmed = $true
        $f.tags      = $tags.ToArray()
        $f.detail    = ("Prefetch records are missing for programs this machine also recorded in other artefacts ({0} - seen in {1}). " -f ($seen -join ', '), $source) +
                       ("{0} core records absent while {1} survived, which is deletion after execution rather than a version-specific difference." -f $missing.Count, $script:PrefetchRecordTotal)
        break
    }
}

function Resolve-FindingConfidence {
    <#
        False-positive control pass. Runs once, just before the verdict:

          1. A Detection that is not confirmed and whose subject appears in only
             one finding is demoted to Warning. One heuristic cannot condemn.
          2. A Detection that is confirmed is always kept.
          3. Two or more findings sharing a subject (or a confirmed + any pair
             across different categories) keep each other as Detections.

        Downgraded rows stay in the report - they are just weighted as warnings,
        so the analyst still sees them without the score lying.
    #>
    $bySubject = @{}
    foreach ($f in $script:Findings) {
        if (-not $f.subject) { continue }
        if (-not $bySubject.ContainsKey($f.subject)) { $bySubject[$f.subject] = New-Object 'System.Collections.Generic.List[object]' }
        $bySubject[$f.subject].Add($f)
    }

    foreach ($f in $script:Findings) {
        if ($f.severity -ne 'Detection') { continue }
        if ($f.confirmed) { continue }

        $group = $bySubject[$f.subject]
        if ($null -ne $group -and $group.Count -ge 2) { continue }

        $f.severity = 'Warning'
        $tagList = New-Object 'System.Collections.Generic.List[string]'
        foreach ($t in $f.tags) { if ($t -ne 'Detection') { $tagList.Add($t) } }
        if (-not $tagList.Contains('Warning')) { $tagList.Add('Warning') }
        $f.tags = $tagList.ToArray()
        $script:Downgraded++
    }
}

function Add-Activity {
    param([Parameter(Mandatory)][string]$Label, [string]$Time = '', [string]$Kind = 'info')
    $script:Activity.Add([pscustomobject]@{ label = $Label; time = $Time; kind = $Kind })
}

function Add-Provider {
    param([string]$Name, [string]$Status, [int]$Matched = 0, [string]$Note = '')
    $script:Providers.Add([pscustomobject]@{
        name    = $Name
        status  = $Status
        matched = $Matched
        note    = $Note
    })
}

function ConvertTo-IsoTime {
    param($Value)
    if ($null -eq $Value) { return '' }
    try {
        if ($Value -is [datetime]) { return $Value.ToLocalTime().ToString('o') }
        if ($Value -is [DateTimeOffset]) { return $Value.LocalDateTime.ToString('o') }
        if ($Value -is [string] -and $Value) { return ([datetime]$Value).ToString('o') }
    }
    catch { }
    return ''
}

function ConvertTo-SafeText {
    param($Value, [int]$Max = 400)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ' '
    $s = $s.Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...' }
    return $s
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Get-SafeProperty {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    try {
        $p = $Object.PSObject.Properties[$Name]
        if ($p -and $null -ne $p.Value) { return $p.Value }
    }
    catch { }
    return $Default
}

# ---------------------------------------------------------------------------
# 2. Phase 1 - system context
# ---------------------------------------------------------------------------

function Get-SystemInfo {
    $info = [ordered]@{}

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1

    $displayVersion = ''
    try {
        $displayVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).DisplayVersion
    }
    catch { }

    $info.osName       = ConvertTo-SafeText (Get-SafeProperty $os 'Caption' 'Windows')
    $info.osBuild      = ConvertTo-SafeText (Get-SafeProperty $os 'BuildNumber' '')
    $info.osVersion    = ConvertTo-SafeText (Get-SafeProperty $os 'Version' '')
    $info.osEdition    = ConvertTo-SafeText $displayVersion
    $info.hostname     = $env:COMPUTERNAME
    $info.username     = $env:USERNAME
    $info.domain       = ConvertTo-SafeText (Get-SafeProperty $cs 'Domain' '')
    $info.cpu          = ConvertTo-SafeText (Get-SafeProperty $cpu 'Name' '')
    $info.cores        = [int](Get-SafeProperty $cpu 'NumberOfCores' 0)
    $info.threads      = [int](Get-SafeProperty $cpu 'NumberOfLogicalProcessors' 0)

    $ramBytes = [int64](Get-SafeProperty $cs 'TotalPhysicalMemory' 0)
    $info.ram = if ($ramBytes -gt 0) { '{0:N1} GB' -f ($ramBytes / 1GB) } else { '' }

    $gpu = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue | Sort-Object -Property AdapterRAM -Descending | Select-Object -First 1
    $info.gpu = ConvertTo-SafeText (Get-SafeProperty $gpu 'Name' '')

    $bootRaw = Get-SafeProperty $os 'LastBootUpTime' $null
    if ($bootRaw) {
        $info.bootTime = ConvertTo-IsoTime $bootRaw
        $script:BootTime = [datetime]$bootRaw
        $info.uptimeMinutes = [int]([Math]::Max(0, ((Get-Date) - [datetime]$bootRaw).TotalMinutes))
    }
    else {
        $info.bootTime = ''
        $info.uptimeMinutes = 0
    }

    $installRaw = Get-SafeProperty $os 'InstallDate' $null
    $info.installDate = if ($installRaw) { ([datetime]$installRaw).ToString('yyyy-MM-dd HH:mm:ss') } else { '' }

    $country = ''
    try { $country = [string](Get-WinHomeLocation -ErrorAction Stop).GeoName } catch { }
    if (-not $country) {
        try { $country = [System.Globalization.RegionInfo]::CurrentRegion.EnglishName } catch { }
    }
    if (-not $country) {
        try { $country = (Get-Culture).EnglishName } catch { }
    }
    if (-not $country) { $country = 'Unknown' }
    $info.country = ConvertTo-SafeText $country

    # --- VPN ----------------------------------------------------------------
    $vpnEvidence = New-Object 'System.Collections.Generic.List[string]'
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
        foreach ($a in $adapters) {
            $blob = "$($a.Name) $($a.InterfaceDescription)"
            if ($blob -match '(?i)(vpn|tap|tun|wireguard|openvpn|nordlynx|wintun|tails|proton|mullvad|clash|v2ray|sing-box|zerotier|tailscale)') {
                $vpnEvidence.Add("adapter: $($a.Name)")
            }
        }
    }
    catch { }

    foreach ($proc in @('openvpn', 'wireguard', 'wg', 'nordvpn', 'mullvad', 'protonvpn', 'surfshark', 'expressvpn', 'warp-svc', 'clash', 'v2ray')) {
        $p = Get-Process -Name $proc -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p) { $vpnEvidence.Add("process: $($p.ProcessName).exe") }
    }

    if (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings') {
        try {
            $proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
            if ($proxy.ProxyEnable -eq 1 -and $proxy.ProxyServer) { $vpnEvidence.Add("proxy: $($proxy.ProxyServer)") }
        }
        catch { }
    }

    $info.vpn = if ($vpnEvidence.Count -gt 0) { 'Yes' } else { 'No' }
    $info.vpnDetail = ($vpnEvidence -join ', ')

    # --- Recycle bin --------------------------------------------------------
    $recycleCount = 0
    $recycleLatest = $null
    $recycleSize = 0
    try {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $binRoot = Join-Path $env:SystemDrive '$Recycle.Bin'
        $binDir = Join-Path $binRoot $sid
        if (Test-Path -LiteralPath $binDir) {
            $items = Get-ChildItem -LiteralPath $binDir -Force -File -ErrorAction SilentlyContinue
            foreach ($it in $items) {
                if ($it.Name -notlike '$R*') { continue }
                $recycleCount++
                $recycleSize += $it.Length
                if ($null -eq $recycleLatest -or $it.LastWriteTime -gt $recycleLatest) { $recycleLatest = $it.LastWriteTime }
            }
        }
    }
    catch { }

    $info.recycleCount = $recycleCount
    $info.recycleSize = $recycleSize
    $info.recycleLatest = if ($recycleLatest) { ConvertTo-IsoTime $recycleLatest } else { '' }

    # --- Game instance ------------------------------------------------------
    # A JVM is only the game when its command line looks like a Minecraft launch.
    # Any other java.exe (Gradle, Kotlin daemon, IDE) must never be treated as the
    # subject, or every dev tool would be accused of injection.
    $javaAll = @()
    try {
        $javaAll = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -ErrorAction SilentlyContinue)
    }
    catch { }

    $gameProc = $null
    foreach ($p in $javaAll) {
        $cmd = [string](Get-SafeProperty $p 'CommandLine' '')
        if ($cmd -match '(?i)(net\.minecraft|minecraft|--gameDir|--assetsDir|-Dminecraft)') { $gameProc = $p; break }
    }
    if (-not $gameProc -and $javaAll.Count -gt 0) {
        $gameProc = $javaAll | Where-Object { $_.Name -eq 'javaw.exe' } | Select-Object -First 1
    }

    $script:InstanceStart = $null
    $info.gameRunning = $false
    $info.gameStart = ''
    $info.gamePid = 0
    $info.gameName = 'Minecraft Java'
    $info.windowText = ''
    $info.gameMemoryMB = 0
    $info.javaProcesses = $javaAll.Count

    if ($gameProc) {
        $startRaw = Get-SafeProperty $gameProc 'CreationDate' $null
        if ($startRaw) { $script:InstanceStart = [datetime]$startRaw }

        $info.gameRunning = $true
        $info.gameStart = ConvertTo-IsoTime $script:InstanceStart
        $info.gamePid = [int]$gameProc.ProcessId

        $gp = Get-Process -Id $info.gamePid -ErrorAction SilentlyContinue
        if ($gp) {
            $info.windowText = ConvertTo-SafeText $gp.MainWindowTitle 120
            $info.gameMemoryMB = [int]($gp.WorkingSet64 / 1MB)
        }
    }
    elseif ($javaAll.Count -gt 0) {
        Add-Finding -Category 'Java Connections' -Title 'Non-Game Java Processes' -Severity 'Info' `
            -Detail ("$($javaAll.Count) java.exe process(es) are running but none match a Minecraft launch. They were excluded from memory, agent and native-module checks.")
    }

    # --- Verdict subtleties -------------------------------------------------
    if ($info.vpn -eq 'Yes') {
        Add-Finding -Category 'Overview' -Title 'VPN Detected' -Severity 'Warning' -Tags @() `
            -Detail "A VPN/proxy layer is active: $($info.vpnDetail). Latency and session evidence may be manipulated."
    }

    if ($info.recycleLatest) {
        $age = (Get-Date) - [datetime]$info.recycleLatest
        if ($age.TotalMinutes -lt 120 -and $recycleCount -gt 0) {
            Add-Finding -Category 'Files Activity' -Title 'Recent Recycle Bin Activity' -Severity 'Warning' `
                -Detail ("$recycleCount item(s) were recycled, most recently {0:N0} minutes ago." -f $age.TotalMinutes) `
                -Time $info.recycleLatest
        }
        else {
            Add-Activity -Label "Recycle bin: $recycleCount item(s)" -Time $info.recycleLatest -Kind 'recycle'
        }
    }

    if ($info.gameRunning) {
        Add-Activity -Label 'Minecraft Java instance started' -Time $info.gameStart -Kind 'game'
        if ($info.windowText) {
            Add-Finding -Category 'Overview' -Title 'Instance Window' -Severity 'Info' -Detail $info.windowText -Time $info.gameStart
        }
    }
    else {
        Add-Finding -Category 'Overview' -Title 'No Java Instance Running' -Severity 'Warning' `
            -Detail 'javaw.exe was not running during this scan - runtime correlation was skipped.'
    }

    if ($info.uptimeMinutes -gt 0 -and $info.uptimeMinutes -lt 10) {
        Add-Finding -Category 'Boot Sequence' -Title 'Very Recent Reboot' -Severity 'Warning' -Tags @('Boot') `
            -Detail ("System uptime is only {0:N0} minute(s). Rebooting right before a screenshare clears runtime artefacts." -f $info.uptimeMinutes)
    }

    return [pscustomobject]$info
}

# ---------------------------------------------------------------------------
# 3. Phase 1 - prefetch / BAM / UserAssist / USN
# ---------------------------------------------------------------------------

function Get-PrefetchData {
    param([Nullable[datetime]]$InstanceStart)

    $result = [pscustomobject]@{
        available       = $false
        accessDenied    = $false
        total           = 0
        items           = @()
        missingBaseline = @()
        newestWrite     = ''
        error           = ''
    }

    $dir = Join-Path $env:WINDIR 'Prefetch'
    try {
        $files = Get-ChildItem -LiteralPath $dir -Filter '*.pf' -Force -File -ErrorAction Stop
        $result.available = $true
    }
    catch {
        $result.accessDenied = $true
        $result.error = $ex = $_.Exception.Message
        Add-Provider -Name 'Prefetch' -Status 'blocked' -Note 'Directory unreadable - BAM/UserAssist used instead'
        Add-Finding -Category 'Files Activity' -Title 'Prefetch ACL Restricted' -Severity 'Warning' `
            -Detail 'The Prefetch directory could not be enumerated. Windows was installed without prefetch, or the ACL hides execution history.'
        return $result
    }

    $result.total = $files.Count
    $names = New-Object 'System.Collections.Generic.HashSet[string]'
    $list = New-Object 'System.Collections.Generic.List[object]'
    $newest = $null

    foreach ($f in $files) {
        $base = $f.BaseName
        $exe = ($base -split '-')[0].ToUpperInvariant()
        [void]$names.Add($exe)
        if ($null -eq $newest -or $f.LastWriteTime -gt $newest) { $newest = $f.LastWriteTime }
        Register-ExecutionEvidence -Path $f.FullName -Time $f.LastWriteTime -Source 'Prefetch'

        $isInteresting = ($exe -match '^(JAVAW|JAVA|EXPLORER|JAVAC)$') -or
            ($script:CheatTokens | Where-Object { $f.Name -match [regex]::Escape($_) })

        if ($isInteresting) {
            $list.Add([pscustomobject]@{
                name = $f.Name
                exe  = $exe
                time = ConvertTo-IsoTime $f.LastWriteTime
                size = $f.Length
            })
        }
    }

    $result.items = $list.ToArray()
    if ($newest) { $result.newestWrite = ConvertTo-IsoTime $newest }

    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($b in $script:BaselinePrefetch) {
        if (-not $names.Contains($b)) { $missing.Add($b) }
    }
    $missingOptional = New-Object 'System.Collections.Generic.List[string]'
    foreach ($b in $script:BaselinePrefetchOptional) {
        if (-not $names.Contains($b)) { $missingOptional.Add($b) }
    }
    $result.missingBaseline = $missing.ToArray()
    $script:PrefetchMissingCore = $missing.ToArray()
    $script:PrefetchRecordTotal = [int]$files.Count

    Add-Provider -Name 'Prefetch' -Status 'ok' -Matched $files.Count -Note "$($files.Count) .pf records"
    if ($newest) { Add-Activity -Label ("Prefetch indexed: {0} records" -f $files.Count) -Time (ConvertTo-IsoTime $newest) -Kind 'prefetch' }

    if ($files.Count -eq 0) {
        Add-Finding -Category 'Files Activity' -Title 'Prefetch Empty' -Severity 'Detection' -Confirmed `
            -Subject 'prefetch-tamper' `
            -Detail 'The Prefetch folder contains no execution records at all. Windows has been cleaned.'
    }
    else {
        # Deliberately NOT a Detection here. Absent prefetch records are only
        # suspicious once a second artefact proves the program did run; that
        # reconciliation happens in Resolve-PrefetchTamper after ShimCache,
        # MuiCache, BAM and UserAssist have been collected.
        $parts = @()
        if ($missing.Count -gt 0) { $parts += ('core: ' + ($missing -join ', ')) }
        if ($missingOptional.Count -gt 0) { $parts += ('version-specific: ' + ($missingOptional -join ', ')) }

        if ($parts.Count -gt 0) {
            Add-Finding -Category 'Files Activity' -Title 'Prefetch Baseline Gaps' -Severity 'Warning' `
                -Subject 'prefetch-tamper' -Tags @('Boot') `
                -Detail ("{0} baseline prefetch record(s) absent while {1} survived ({2}). Checked against ShimCache/BAM to decide whether anything was actually deleted." -f ($missing.Count + $missingOptional.Count), $files.Count, ($parts -join '; '))
        }
        else {
            Add-Finding -Category 'Files Activity' -Title 'Prefetch Intact' -Severity 'Legit' `
                -Detail ("$($files.Count) execution records present, including every baseline system process.")
        }
    }

    # Prefetch folder ACL: a Deny ACE on SYSTEM/Administrators is deliberate
    # tampering - the collector then silently stops recording executions.
    try {
        $acl = Get-Acl -LiteralPath $dir -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Deny') { continue }
            $who = [string]$ace.IdentityReference
            if ($who -notmatch '(?i)^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|CREATOR OWNER)$') { continue }
            Add-Finding -Category 'Files Activity' -Title 'Prefetch ACL Deny Rule' -Severity 'Detection' `
                -Confirmed -Subject 'prefetch-tamper' -Tags @('Boot') `
                -Detail ("{0} has an explicit Deny ACE for {1} on {2}. Execution recording for that principal is disabled on purpose." -f $dir, $who, ($ace.FileSystemRights -join ','))
            break
        }
    }
    catch { }

    # Execution correlation for the game client itself.
    $javaRecord = $list | Where-Object { $_.exe -eq 'JAVAW' } | Sort-Object { $_.time } -Descending | Select-Object -First 1
    if ($javaRecord) {
        if ($InstanceStart) {
            $delta = ([datetime]$javaRecord.time) - [datetime]$InstanceStart
            if ([Math]::Abs($delta.TotalMinutes) -le 15) {
                Add-Finding -Category 'Java Connections' -Title 'Java Prefetch Matches Instance' -Severity 'Legit' `
                    -Detail ("JAVAW.EXE prefetch write is {0:N0} min from javaw.exe StartTime - execution timeline consistent." -f $delta.TotalMinutes) `
                    -Time $javaRecord.time
            }
            else {
                Add-Finding -Category 'Java Connections' -Title 'Java Prefetch Time Discrepancy' -Severity 'Warning' -Tags @('Boot') `
                    -Detail ("JAVAW.EXE prefetch write differs from the running instance by {0:N0} min - an older session is hidden here." -f $delta.TotalMinutes)
            }
        }
        Add-Activity -Label 'JAVAW.EXE prefetch record last written' -Time $javaRecord.time -Kind 'prefetch'
    }

    return $result
}

function ConvertFrom-BamTime {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 8) { return $null }
    $offsets = @(0, 8)
    if ($Bytes.Length -ge 24) { $offsets += 16 }
    foreach ($off in $offsets) {
        if ($Bytes.Length -lt ($off + 8)) { continue }
        try {
            $ft = [BitConverter]::ToInt64($Bytes, $off)
            if ($ft -le 0) { continue }
            $dt = [datetime]::FromFileTime($ft)
            if ($dt.Year -ge 2005 -and $dt -le (Get-Date).AddDays(2)) { return $dt }
        }
        catch { }
    }
    return $null
}

function Get-BamData {
    param([Nullable[datetime]]$InstanceStart)

    $entries = New-Object 'System.Collections.Generic.List[object]'
    $roots = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
    )
    $readable = $false

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        try {
            $sids = Get-ChildItem -Path $root -ErrorAction Stop
            $readable = $true
        }
        catch { continue }

        foreach ($sidKey in $sids) {
            try {
                $key = Get-Item -LiteralPath $sidKey.PSPath -ErrorAction Stop
                $names = $key.GetValueNames()
            }
            catch { continue }

            foreach ($name in $names) {
                if ($name -match '^$' -or $name -eq 'SequenceNumber' -or $name -eq 'Version') { continue }
                try {
                    $bytes = $key.GetValue($name)
                }
                catch { continue }
                if ($bytes -isnot [byte[]]) { continue }
                $time = ConvertFrom-BamTime -Bytes $bytes
                if ($null -eq $time) { continue }
                $entries.Add([pscustomobject]@{ path = $name; time = $time })
                Register-ExecutionEvidence -Path $name -Time $time -Source 'BAM'
            }
        }
    }

    if (-not $readable) {
        Add-Provider -Name 'BAM' -Status 'blocked' -Note 'Requires elevation to read HKLM bam hive'
        Add-Finding -Category 'Files Activity' -Title 'BAM Unreadable' -Severity 'Warning' `
            -Detail 'Execution timestamps from the Background Activity Moderator could not be read (needs elevation).'
        return @()
    }

    Add-Provider -Name 'BAM' -Status 'ok' -Matched $entries.Count -Note "$($entries.Count) executions"

    $interesting = $entries | Where-Object {
        $p = $_.path
        if ($p -match '(?i)\\(javaw|java|explorer)\.exe$') { return $true }
        foreach ($t in $script:CheatTokens) { if ($p -match [regex]::Escape($t)) { return $true } }
        return $false
    }

    foreach ($e in $interesting) {
        $leaf = Split-Path -Leaf $e.path
        if ($leaf -match '(?i)^(javaw|java)\.exe$') {
            Add-Activity -Label "BAM: $leaf executed" -Time (ConvertTo-IsoTime $e.time) -Kind 'bam'
            continue
        }
        $correlated = $false
        if ($InstanceStart) {
            $delta = ([datetime]$e.time) - [datetime]$InstanceStart
            $correlated = $delta.TotalMinutes -gt -180 -and $delta.TotalMinutes -lt 20
        }

        if ($correlated) {
            Add-Finding -Category 'Cheater Records' -Title ("BAM Execution: $leaf") -Severity 'Detection' -Confirmed `
                -Subject $leaf -Tags @('In Instance') `
                -Detail ("{0} executed {1:N0} min from the Minecraft instance start. Path: {2}" -f $leaf, (([datetime]$e.time) - [datetime]$InstanceStart).TotalMinutes, $e.path) `
                -Time (ConvertTo-IsoTime $e.time)
        }
        else {
            Add-Finding -Category 'Cheater Records' -Title ("Historic Execution: $leaf") -Severity 'Warning' `
                -Detail ("{0} executed previously (no correlation with this session). Path: {1}" -f $leaf, $e.path) `
                -Time (ConvertTo-IsoTime $e.time)
        }
    }

    if ($InstanceStart) {
        $java = $entries | Where-Object { $_.path -match '(?i)\\javaw\.exe$' } | Sort-Object time -Descending | Select-Object -First 1
        if ($java) {
            $delta = ([datetime]$java.time) - [datetime]$InstanceStart
            if ([Math]::Abs($delta.TotalMinutes) -lt 10) {
                Add-Finding -Category 'Java Connections' -Title 'BAM Confirms Instance Start' -Severity 'Legit' `
                    -Detail ("javaw.exe last-executed timestamp is {0:N1} min from the live process start." -f $delta.TotalMinutes)
            }
        }
    }

    return $entries.ToArray()
}

function ConvertFrom-Rot13 {
    param([string]$Text)
    if (-not $Text) { return '' }
    $chars = $Text.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = [int]$chars[$i]
        if ($c -ge 97 -and $c -le 122) { $chars[$i] = [char]((((($c - 97) + 13) % 26) + 97)) }
        elseif ($c -ge 65 -and $c -le 90) { $chars[$i] = [char]((((($c - 65) + 13) % 26) + 65)) }
    }
    return (-join $chars)
}

function Get-UserAssistData {
    param([Nullable[datetime]]$InstanceStart)

    $root = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    if (-not (Test-Path $root)) {
        Add-Provider -Name 'UserAssist' -Status 'missing'
        return @()
    }

    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($guid in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
        $countPath = Join-Path $guid.PSPath 'Count'
        if (-not (Test-Path $countPath)) { continue }
        try { $key = Get-Item -LiteralPath $countPath -ErrorAction Stop } catch { continue }

        foreach ($name in $key.GetValueNames()) {
            if (-not $name) { continue }
            $decoded = ConvertFrom-Rot13 $name
            try { $bytes = $key.GetValue($name) } catch { continue }
            if ($bytes -isnot [byte[]] -or $bytes.Length -lt 68) { continue }
            $runs = [BitConverter]::ToInt32($bytes, 4)
            $time = $null
            try { $time = [datetime]::FromFileTime([BitConverter]::ToInt64($bytes, 60)) } catch { }
            if ($null -eq $time -or $time.Year -lt 2005) { continue }
            $entries.Add([pscustomobject]@{ name = $decoded; runs = $runs; time = $time })
            Register-ExecutionEvidence -Path $decoded -Time $time -Source 'UserAssist'
        }
    }

    Add-Provider -Name 'UserAssist' -Status 'ok' -Matched $entries.Count -Note "$($entries.Count) GUI launches"

    foreach ($e in $entries) {
        $hit = $false
        foreach ($t in $script:CheatTokens) { if ($e.name -match [regex]::Escape($t)) { $hit = $true; break } }
        if (-not $hit) { continue }

        $correlated = $false
        if ($InstanceStart) {
            $d = ($e.time - [datetime]$InstanceStart).TotalMinutes
            $correlated = $d -gt -240 -and $d -lt 20
        }
        if ($correlated) {
            Add-Finding -Category 'Cheater Records' -Title 'UserAssist Shell Launch' -Severity 'Detection' -Confirmed `
                -Subject (Get-LeafName $e.name) -Tags @('In Instance') `
                -Detail ("{0} was launched from Explorer {1} time(s), most recently {2:N0} min from the instance start." -f $e.name, $e.runs, (($e.time - [datetime]$InstanceStart).TotalMinutes)) `
                -Time (ConvertTo-IsoTime $e.time)
        }
        else {
            Add-Finding -Category 'Cheater Records' -Title 'UserAssist Historic Launch' -Severity 'Warning' `
                -Detail ("{0} appears in UserAssist ({1} run(s)) but outside the current session window." -f $e.name, $e.runs) `
                -Time (ConvertTo-IsoTime $e.time)
        }
    }

    return $entries.ToArray()
}

function Invoke-UsnQuery {
    param([int]$TimeoutSeconds = 25)

    $result = [pscustomobject]@{ available = $false; partial = $false; lines = 0; hits = @(); error = '' }
    $tmp = $null
    try {
        $tmp = [IO.Path]::GetTempFileName()
        $proc = Start-Process -FilePath 'fsutil.exe' -ArgumentList 'usn', 'readjournal', 'C:', 'csv' `
            -RedirectStandardOutput $tmp -RedirectStandardError ($tmp + '.err') -NoNewWindow -PassThru -ErrorAction Stop

        $finished = $proc.WaitForExit($TimeoutSeconds * 1000)
        if (-not $finished) {
            try { $proc.Kill() } catch { }
            $result.partial = $true
        }

        $errText = ''
        if (Test-Path -LiteralPath ($tmp + '.err')) { $errText = (Get-Content -LiteralPath ($tmp + '.err') -Raw -ErrorAction SilentlyContinue) }

        if ($errText -and $errText -match '(?i)(access is denied|requires elevation|not elevated|administrator)') {
            $result.error = 'elevation required'
            Add-Provider -Name 'USN Journal' -Status 'blocked' -Note 'Requires an elevated shell'
            Add-Finding -Category 'Files Activity' -Title 'USN Journal Unavailable' -Severity 'Warning' `
                -Detail 'fsutil usn readjournal needs an elevated shell - deletion history was not inspected.'
            return $result
        }

        if (-not (Test-Path -LiteralPath $tmp)) {
            $result.error = 'no output'
            return $result
        }

        $content = Get-Content -LiteralPath $tmp -ErrorAction SilentlyContinue
        if ($null -eq $content) { $content = @() }
        $result.lines = @($content).Count
        if ($result.lines -lt 2) {
            $result.error = 'journal unavailable'
            Add-Provider -Name 'USN Journal' -Status 'blocked' -Note 'fsutil returned no journal data (elevation required)'
            Add-Finding -Category 'Files Activity' -Title 'USN Journal Unavailable' -Severity 'Warning' `
                -Detail 'fsutil usn readjournal produced no data. Deletion history needs an elevated shell.'
            return $result
        }
        $result.available = $true

        # Each CSV row: Usn, File name, Reason, Timestamp, ... - we only need names.
        $hits = New-Object 'System.Collections.Generic.List[string]'
        $deletions = 0
        foreach ($line in $content) {
            if ($line -match 'FILE_DELETE') { $deletions++ }
            foreach ($t in $script:CheatTokens) {
                if ($line -match [regex]::Escape($t)) {
                    $safe = ConvertTo-SafeText $line 180
                    if (-not $hits.Contains($safe)) { $hits.Add($safe) }
                    break
                }
            }
        }

        $result.hits = $hits.ToArray()
        Add-Provider -Name 'USN Journal' -Status 'ok' -Matched $result.lines -Note ("{0} journal rows, {1} delete records" -f $result.lines, $deletions)

        if ($result.partial) {
            Add-Finding -Category 'Files Activity' -Title 'USN Journal Partially Read' -Severity 'Info' `
                -Detail ("Journal is large; the first {0:N0} rows were parsed before the {1}s budget expired." -f $result.lines, $TimeoutSeconds)
        }

        foreach ($h in $result.hits) {
            # A delete record alone proves the file EXISTED. It becomes a
            # Detection only when another source proves it RAN - the classic
            # "executed and then wiped" ghost artefact.
            $leaf = $h
            if ($h -match '^"?\d+"?\s*,\s*"([^"]+)"') { $leaf = $Matches[1] }
            elseif ($h -match ',\s*"([^"]+)"') { $leaf = $Matches[1] }
            $leaf = Split-Path -Leaf $leaf
            if (-not $leaf) { $leaf = $h }

            $corr = Test-ExecutionCorrelation -PathOrName $leaf
            if ($corr.executed) {
                Add-Finding -Category 'Files Activity' -Title ("Executed & Deleted: $leaf") -Severity 'Detection' `
                    -Confirmed -Subject $leaf -Tags @('Boot') `
                    -Detail ("{0} was executed (source: {1}) and is now gone from disk - antiforensic cleanup. Journal row: {2}" -f $leaf, $corr.source, $h)
            }
            else {
                Add-Finding -Category 'Files Activity' -Title ("Deleted Artefact (USN): $leaf") -Severity 'Warning' `
                    -Subject $leaf -Tags @('Boot') `
                    -Detail ("{0} was deleted; no execution record was found for it, so this is cleanup evidence only. Row: {1}" -f $leaf, $h)
            }
        }

        if ($result.hits.Count -eq 0 -and $deletions -gt 0) {
            Add-Activity -Label ("USN journal: {0:N0} delete records, no cheat names" -f $deletions) -Kind 'usn'
        }
    }
    catch {
        $result.error = $_.Exception.Message
        Add-Provider -Name 'USN Journal' -Status 'failed' -Note $result.error
    }
    finally {
        foreach ($f in @($tmp, "$tmp.err")) {
            if ($f -and (Test-Path -LiteralPath $f)) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# 3b. ShimCache (AppCompatCache) + MuiCache
# ---------------------------------------------------------------------------

function Get-ShimCacheData {
    <#
        AppCompatCache records images the boot/session process handled, and
        MuiCache records programs launched by this user. Both are read-only
        registry reads; neither is ever written back.
    #>
    param([Nullable[datetime]]$InstanceStart)

    $result = [pscustomobject]@{ available = $false; shim = 0; mui = 0; hits = @(); error = '' }

    # --- AppCompatCache -----------------------------------------------------
    $blob = $null
    foreach ($keyPath in @(
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache',
            'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache'
        )) {
        try {
            if (-not (Test-Path -LiteralPath $keyPath)) { continue }
            $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop
            foreach ($vn in $key.GetValueNames()) {
                $v = $null
                try { $v = $key.GetValue($vn) } catch { continue }
                if ($v -is [byte[]] -and $v.Length -gt 64) { $blob = $v; break }
            }
        }
        catch { }
        if ($blob) { break }
    }

    $shimPaths = @()
    if ($blob -and ('OceanShimCache' -as [type])) {
        try { $shimPaths = @([OceanShimCache]::ExtractPaths($blob, 8, 400)) } catch { $shimPaths = @() }
        $result.available = $shimPaths.Count -gt 0
        $result.shim = $shimPaths.Count
        foreach ($p in $shimPaths) { Register-ExecutionEvidence -Path $p -Time $null -Source 'ShimCache' }
    }

    if (-not $result.available) {
        $result.error = 'AppCompatCache unreadable or unsupported format'
        Add-Provider -Name 'ShimCache' -Status 'blocked' -Note $result.error
    }
    else {
        Add-Provider -Name 'ShimCache' -Status 'ok' -Matched $result.shim -Note "$($result.shim) image paths"
    }

    # --- MuiCache -----------------------------------------------------------
    $hits = New-Object 'System.Collections.Generic.List[string]'
    $muiRoot = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
    try {
        if (Test-Path -LiteralPath $muiRoot) {
            $mui = Get-Item -LiteralPath $muiRoot -ErrorAction Stop
            foreach ($vn in $mui.GetValueNames()) {
                if (-not $vn -or $vn -notmatch '(?i)\.exe') { continue }
                $result.mui++
                Register-ExecutionEvidence -Path $vn -Time $null -Source 'MuiCache'
                foreach ($t in $script:CheatTokens) {
                    if ($vn -match [regex]::Escape($t)) {
                        $safe = ConvertTo-SafeText $vn 180
                        if (-not $hits.Contains($safe)) { $hits.Add($safe) }
                        break
                    }
                }
            }
        }
    }
    catch { }

    Add-Provider -Name 'MuiCache' -Status 'ok' -Matched $result.mui -Note "$($result.mui) program records"
    foreach ($h in $hits) {
        $leaf = Split-Path -Leaf $h
        $corr = Test-ExecutionCorrelation -PathOrName $leaf
        Add-Finding -Category 'Cheater Records' -Title "Launched Program: $leaf" -Severity 'Detection' `
            -Confirmed -Subject $leaf -Tags @('In Instance') `
            -Detail ("{0} was launched from this account (MuiCache{1})." -f $h, $(if ($corr.executed) { "; corroborated by $($corr.source)" } else { '' }))
    }

    $result.hits = $hits.ToArray()
    return $result
}

# ---------------------------------------------------------------------------
# 4. Phase 4 - registry, shell history, DNS
# ---------------------------------------------------------------------------

function Get-RegistryArtifacts {
    $artifacts = [pscustomobject]@{ uninstall = @(); classes = @(); autoruns = @(); teamspeak = $null; hits = 0 }
    $hits = New-Object 'System.Collections.Generic.List[object]'

    # --- Installed programs -------------------------------------------------
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $count = 0
    foreach ($root in $uninstallRoots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($k in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            try { $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
            $count++
            $name = [string]$props.DisplayName
            if (-not $name) { continue }
            foreach ($t in $script:CheatTokens) {
                if ($name -match [regex]::Escape($t)) {
                    $hits.Add([pscustomobject]@{
                            where = 'Uninstall'
                            token = $t
                            what  = $name
                            extra = ConvertTo-SafeText ([string]$props.InstallLocation) 160
                        })
                    break
                }
            }
        }
    }
    $artifacts.uninstall = $count

    # --- Vape's TeamSpeak marker + protocol handlers ------------------------
    $tsPath = 'HKCU:\SOFTWARE\Teamspeak 3 Client'
    if (Test-Path $tsPath) {
        try {
            $ts = Get-ItemProperty -LiteralPath $tsPath -ErrorAction Stop
            if ($null -ne $ts.tim) {
                $artifacts.teamspeak = "tim=$($ts.tim)"
                $hits.Add([pscustomobject]@{
                        where = 'Teamspeak'
                        token = 'vape'
                        what  = 'HKCU\Software\Teamspeak 3 Client\tim present (Vape V4 watermark)'
                        extra = "value: $($ts.tim)"
                    })
            }
        }
        catch { }
    }

    # --- Classes / protocol handlers ---------------------------------------
    $classRoots = @('HKCU:\Software\Classes', 'HKLM:\SOFTWARE\Classes', 'HKLM:\SOFTWARE\WOW6432Node\Classes')
    $classTokens = @('vapeclient', 'vape', 'prestigeclient', 'prestige', 'liquidbounce', 'orchardclient')
    foreach ($root in $classRoots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($sub in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            foreach ($t in $classTokens) {
                if ($sub.PSChildName -match $t) {
                    $keyPath = $sub.PSPath
                    $cmd = ''
                    try {
                        $cmdKey = Join-Path $keyPath 'shell\open\command'
                        if (Test-Path $cmdKey) { $cmd = [string](Get-ItemProperty -LiteralPath $cmdKey).'(default)' }
                    }
                    catch { }                    $hits.Add([pscustomobject]@{
                            where = 'Classes'
                            token = $t
                            what  = "Handler/class registered: $($sub.PSChildName)"
                            extra = ConvertTo-SafeText $cmd 160
                        })
                    break
                }
            }
        }
    }
    $artifacts.classes = 1

    # --- Autoruns -----------------------------------------------------------
    $runRoots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($root in $runRoots) {
        if (-not (Test-Path $root)) { continue }
        try { $run = Get-ItemProperty -LiteralPath $root -ErrorAction Stop } catch { continue }
        foreach ($p in $run.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $value = [string]$p.Value
            foreach ($t in $script:CheatTokens) {                if (($p.Name -match [regex]::Escape($t)) -or ($value -match [regex]::Escape($t))) {
                    $hits.Add([pscustomobject]@{
                            where = 'Autorun'
                            token = $t
                            what  = "$($p.Name) -> $value"
                            extra = $root
                        })
                    break
                }
            }
        }
    }

    foreach ($h in $hits) {
        # Installing, registering or autorunning a cheat client is a deliberate
        # act with no innocent explanation, so these stay confirmed detections.
        Add-Finding -Category 'Cheater Records' -Title ("Registry $($h.where): $($h.token)") -Severity 'Detection' `
            -Confirmed -Subject $(if ($h.token) { $h.token } else { $h.where }) `
            -Detail ("{0} | {1}" -f $h.what, $h.extra)
    }

    $artifacts.hits = $hits.Count
    Add-Provider -Name 'Registry' -Status 'ok' -Matched $count -Note "$count uninstall entries, $($hits.Count) hits"

    if ($hits.Count -eq 0) {
        Add-Finding -Category 'Cheater Records' -Title 'Registry Clean' -Severity 'Legit' `
            -Detail 'No cheat installers, protocol handlers, TeamSpeak markers or autoruns were found.'
    }

    return $artifacts
}

function Get-DnsArtifacts {
    $records = @()
    try { $records = @(Get-DnsClientCache -ErrorAction Stop) }
    catch {
        Add-Provider -Name 'DNS Cache' -Status 'blocked' -Note 'Get-DnsClientCache unavailable or empty'
    }

    $hits = New-Object 'System.Collections.Generic.List[string]'
    $total = $records.Count

    foreach ($r in $records) {
        $name = [string]$r.Entry
        if (-not $name) { continue }
        foreach ($d in $script:CheatDomains) {
            if ($name -match [regex]::Escape($d)) {
                $line = "$name -> $(ConvertTo-SafeText ([string]$r.Data) 60)"
                if (-not $hits.Contains($line)) { $hits.Add($line) }
                break
            }
        }
    }

    $hostsPath = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    if (Test-Path $hostsPath) {
        try {
            foreach ($line in (Get-Content -LiteralPath $hostsPath -ErrorAction Stop)) {
                if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
                foreach ($d in $script:CheatDomains) {
                    if ($line -match [regex]::Escape($d)) {
                        $safe = ConvertTo-SafeText $line 160
                        if (-not $hits.Contains($safe)) { $hits.Add($safe) }
                        break
                    }
                }
            }
        }
        catch { }
    }

    Add-Provider -Name 'DNS Cache' -Status 'ok' -Matched $total -Note "$total cached entries"

    foreach ($h in $hits) {
        $hostName = ($h -split ' -> ')[0]
        # Resolving a cheat domain is network activity, not a stray string.
        Add-Finding -Category 'Suspicious logs' -Title "Cheat Domain Resolved: $hostName" -Severity 'Detection' `
            -Confirmed -Subject $hostName -Detail $h
    }
    if ($hits.Count -eq 0) {
        Add-Finding -Category 'Suspicious logs' -Title 'DNS Cache Clean' -Severity 'Legit' `
            -Detail "$total cached entries, none matching a known cheat endpoint."
    }

    return [pscustomobject]@{ total = $total; hits = $hits.ToArray() }
}

# ---------------------------------------------------------------------------
# 5. Phase 1 - concurrent hash verification (Modrinth / Megabase)
# ---------------------------------------------------------------------------

$script:HashWorker = {
    param([string[]]$Batch, [string]$Provider, [string[]]$Endpoints)

    $result = [pscustomobject]@{ provider = $Provider; status = 'ok'; note = ''; map = @{} }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    $payload = @{ hashes = $Batch; algorithm = 'sha1' } | ConvertTo-Json -Compress
    $headers = @{ 'User-Agent' = 'OceanSS/1.0 (local screenshare tool)'; 'Accept' = 'application/json' }
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $answered = $false

    foreach ($ep in $Endpoints) {
        try {
            $resp = Invoke-RestMethod -Method Post -Uri $ep -Body $payload -ContentType 'application/json' `
                -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        }
        catch {
            $errors.Add("$ep :: $($_.Exception.Message)")
            continue
        }

        $answered = $true
        $map = @{}
        if ($null -eq $resp) { continue }

        $props = @()
        try { $props = $resp.PSObject.Properties } catch { $props = @() }

        if ($props -and $props.Count -gt 0 -and $props[0].Name -match '^[0-9a-f]{40}$') {
            foreach ($p in $props) {
                $v = $p.Value
                $label = $null
                foreach ($candidate in @('version_number', 'name', 'project_id', 'id')) {
                    $cp = $null
                    try { $cp = $v.PSObject.Properties[$candidate] } catch { }
                    if ($cp -and $cp.Value) { $label = [string]$cp.Value; break }
                }
                if (-not $label) { $label = 'verified' }
                $map[$p.Name.ToLowerInvariant()] = $label
            }
        }
        elseif ($resp -is [System.Collections.IEnumerable] -and -not ($resp -is [string])) {
            foreach ($item in $resp) {
                $hash = $null
                foreach ($hf in @('hash', 'sha1', 'file_hash')) {
                    $hp = $null
                    try { $hp = $item.PSObject.Properties[$hf] } catch { }
                    if ($hp -and $hp.Value) { $hash = [string]$hp.Value; break }
                }
                if (-not $hash) { continue }
                $label = $null
                foreach ($lf in @('version_number', 'name', 'project_id', 'id')) {
                    $lp = $null
                    try { $lp = $item.PSObject.Properties[$lf] } catch { }
                    if ($lp -and $lp.Value) { $label = [string]$lp.Value; break }
                }
                if (-not $label) { $label = 'verified' }
                $map[$hash.ToLowerInvariant()] = $label
            }
        }

        if ($map.Count -gt 0) {
            $result.map = $map
            $result.status = 'ok'
            $result.note = "$($map.Count)/$($Batch.Count) matched via $ep"
            return $result
        }
        $errors.Add("$ep :: answered without matches")
    }

    if ($answered) {
        $result.status = 'ok'
        $result.note = "0/$($Batch.Count) matched - repository answered, file is not a published mod"
        return $result
    }

    $result.status = 'unavailable'
    $result.note = ($errors | Select-Object -First 2) -join ' | '
    return $result
}

# CurseForge uses MurmurHash2 fingerprints and a paid-but-free-tier API key, so
# it runs as its own job and degrades to "skipped" when no key is configured.
$script:CurseForgeWorker = {
    param([string[]]$Batch, [string]$ApiKey)

    $result = [pscustomobject]@{ provider = 'CurseForge'; status = 'ok'; note = ''; map = @{} }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    $headers = @{ 'X-API-Key' = $ApiKey; 'Accept' = 'application/json'; 'User-Agent' = 'OceanSS/2.0 (local screenshare tool)' }
    $payload = @{ fingerprints = @($Batch) } | ConvertTo-Json -Compress

    try {
        $resp = Invoke-RestMethod -Method Post -Uri 'https://api.curseforge.com/v1/fingerprints/432' `
            -Body $payload -ContentType 'application/json' -Headers $headers -TimeoutSec 15 -ErrorAction Stop
    }
    catch {
        $result.status = 'unavailable'
        $result.note = $_.Exception.Message
        return $result
    }

    $map = @{}
    try {
        foreach ($match in @($resp.data.exactMatches)) {
            $fp = $null
            $label = $null
            try { $fp = [string]$match.file.fileFingerprint } catch { }
            if (-not $fp) { continue }
            foreach ($candidate in @('fileName', 'displayName', 'id')) {
                try {
                    $v = $match.file.$candidate
                    if ($v) { $label = [string]$v; break }
                }
                catch { }
            }
            if (-not $label) {
                try { if ($match.project.name) { $label = [string]$match.project.name } } catch { }
            }
            if (-not $label) { $label = 'verified' }
            $map[$fp.ToLowerInvariant()] = $label
        }
    }
    catch {
        $result.status = 'unavailable'
        $result.note = $_.Exception.Message
        return $result
    }

    if ($map.Count -gt 0) {
        $result.map = $map
        $result.note = "$($map.Count)/$($Batch.Count) matched via api.curseforge.com"
        return $result
    }

    $result.note = "0/$($Batch.Count) matched - CurseForge answered, file is not a published mod"
    return $result
}

function Start-HashCheck {
    <#
        Fire-and-forget: one background job per provider per hash batch so the
        network round-trips overlap with the local collectors. Jobs are
        dispatched 250 ms apart to stay well inside the public rate limits.
        Pair with Complete-HashCheck.
    #>
    param($Jars)

    $items = @()
    if ($null -ne $Jars) { if ($Jars -is [array]) { $items = $Jars } else { $items = $Jars.ToArray() } }

    $sha1List = New-Object 'System.Collections.Generic.List[string]'
    $cfMap = @{}
    foreach ($j in $items) {
        if ($j -and $j.sha1) { $sha1List.Add([string]$j.sha1) }
        if ($j -and $j.cf) { $cfMap[[string]$j.cf] = [string]$j.sha1 }
    }

    $context = [pscustomobject]@{ jobs = @(); cfMap = $cfMap; empty = $false; curseKey = ''; curseSkipped = '' }

    $uniqueSha = @($sha1List | Sort-Object -Unique)
    if ($uniqueSha.Count -eq 0) {
        Add-Provider -Name 'Modrinth' -Status 'skipped' -Note 'No jars to verify'
        $context.empty = $true
        return $context
    }

    $batchSize = 90
    $batches = @()
    for ($i = 0; $i -lt $uniqueSha.Count; $i += $batchSize) {
        $end = [Math]::Min($i + $batchSize - 1, $uniqueSha.Count - 1)
        $batches += , @($uniqueSha[$i..$end])
    }

    $modrinthEndpoints = @('https://api.modrinth.com/v2/version_files')

    $key = $CurseForgeKey
    if (-not $key) { $key = $env:CURSEFORGE_API_KEY }
    $cfBatchValues = @($cfMap.Keys)

    $jobs = @()
    foreach ($batch in $batches) {
        $jobs += Start-Job -ScriptBlock $script:HashWorker -ArgumentList $batch, 'Modrinth', $modrinthEndpoints
        Start-Sleep -Milliseconds 250
    }

    if ($key -and $cfBatchValues.Count -gt 0) {
        for ($i = 0; $i -lt $cfBatchValues.Count; $i += $batchSize) {
            $end = [Math]::Min($i + $batchSize - 1, $cfBatchValues.Count - 1)
            $slice = @($cfBatchValues[$i..$end])
            $jobs += Start-Job -ScriptBlock $script:CurseForgeWorker -ArgumentList $slice, $key
            Start-Sleep -Milliseconds 250
        }
        $context.curseKey = 'configured'
    }
    else {
        $context.curseSkipped = 'no CURSEFORGE_API_KEY / -CurseForgeKey configured'
    }

    $context.jobs = @($jobs)
    return $context
}

function Complete-HashCheck {
    param($Context)

    $verified = @{}
    if ($null -eq $Context) { return $verified }
    if ($Context.empty) { return $verified }
    $jobs = @($Context.jobs)
    $cfMap = @{}
    if ($Context.cfMap) { $cfMap = $Context.cfMap }

    $collected = @()
    if ($jobs.Count -gt 0) {
        $done = Wait-Job -Job $jobs -Timeout 40
        if ($done) { $collected = Receive-Job -Job $done -ErrorAction SilentlyContinue }
        $stale = $jobs | Where-Object { $_.State -eq 'Running' }
        foreach ($j in $stale) { try { Stop-Job -Job $j -ErrorAction SilentlyContinue } catch { } }
        Remove-Job -Job $jobs -Force -ErrorAction SilentlyContinue
    }

    $statusByProvider = @{}
    foreach ($res in $collected) {
        if (-not $res) { continue }
        $provider = $res.provider
        if (-not $statusByProvider.ContainsKey($provider)) {
            $statusByProvider[$provider] = [pscustomobject]@{ ok = 0; matched = 0; note = ''; status = 'unavailable' }
        }
        $s = $statusByProvider[$provider]
        if ($res.status -eq 'ok') {
            $s.ok++
            $s.status = 'ok'
            $s.note = $res.note
            foreach ($k in @($res.map.Keys)) {
                $shaKey = [string]$k
                if ($provider -eq 'CurseForge') {
                    # CurseForge keys its map by MurmurHash fingerprint; translate
                    # back to the SHA-1 the inventory is indexed by.
                    if (-not $cfMap.ContainsKey($shaKey)) { continue }
                    $shaKey = [string]$cfMap[$shaKey]
                }
                if (-not $shaKey) { continue }
                $shaKey = $shaKey.ToLowerInvariant()
                $s.matched++
                if (-not $verified.ContainsKey($shaKey)) {
                    $verified[$shaKey] = [pscustomobject]@{ provider = $provider; label = $res.map[$k] }
                }
            }
        }
        elseif (-not $s.note) {
            $s.note = $res.note
        }
    }

    foreach ($name in @('Modrinth', 'CurseForge')) {
        if ($statusByProvider.ContainsKey($name)) {
            $s = $statusByProvider[$name]
            Add-Provider -Name $name -Status $s.status -Matched $s.matched -Note $s.note
        }
        elseif ($name -eq 'CurseForge' -and $Context.curseSkipped) {
            Add-Provider -Name $name -Status 'skipped' -Note $Context.curseSkipped
        }
        else {
            Add-Provider -Name $name -Status 'unavailable' -Note 'No response within timeout'
        }
    }

    if ($verified.Count -eq 0) {
        $anyAnswered = $false
        foreach ($k in $statusByProvider.Keys) { if ($statusByProvider[$k].status -eq 'ok') { $anyAnswered = $true; break } }
        if ($anyAnswered) {
            Add-Finding -Category 'Minecraft Mods' -Title 'No Verified Hashes' -Severity 'Info' `
                -Detail 'The repositories answered and none of these jars are published files. They fall back to heuristic review.'
        }
        else {
            Add-Finding -Category 'Minecraft Mods' -Title 'Hash Verification Unavailable' -Severity 'Info' `
                -Detail 'No repository could be reached, so no jar could be whitelisted. This is a network problem, not evidence.'
        }
    }
    else {
        Add-Finding -Category 'Minecraft Mods' -Title ("Hash Verified [{0} files]" -f $verified.Count) -Severity 'Legit' `
            -Detail 'These files exist on a public mod repository and were removed from obfuscation and memory review.'
    }

    return $verified
}

function Invoke-HashCheck {
    <#  Blocking convenience wrapper used by -NoServer / scripted runs. #>
    param($Jars)
    return Complete-HashCheck -Context (Start-HashCheck -Jars $Jars)
}

# ---------------------------------------------------------------------------
# 6. Phase 2 - jar inventory, entropy and entry signatures
# ---------------------------------------------------------------------------

$script:ForensicsSource = @'
using System;

public static class OceanForensics
{
    public static double Entropy(byte[] data, int length)
    {
        if (data == null || length <= 0) { return 0.0; }
        int[] counts = new int[256];
        for (int i = 0; i < length; i++) { counts[data[i]]++; }
        double e = 0.0;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) { continue; }
            double p = (double)counts[i] / (double)length;
            e -= p * Math.Log(p, 2.0);
        }
        return e;
    }

    public static int CountFullwidth(string text)
    {
        if (text == null) { return 0; }
        int n = 0;
        foreach (char c in text)
        {
            if ((c >= '\uFF01' && c <= '\uFF5E') || (c >= '\uFFE0' && c <= '\uFFE6') || c == '\u3000') { n++; }
        }
        return n;
    }
}

public static class OceanFingerprint
{
    // CurseForge identifies files with MurmurHash2 (32-bit) over the raw bytes,
    // not with SHA-1. A wrong value can only mean "no match", never a false
    // whitelist entry, so a seed mismatch degrades to fewer verified jars
    // instead of a wrong verdict.
    public static uint Murmur2(byte[] data, int length, uint seed)
    {
        if (data == null || length <= 0) { return 0; }

        unchecked
        {
            uint h = seed ^ (uint)length;
            int l = length;
            int i = 0;

            while (l >= 4)
            {
                uint k = (uint)(data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24));
                k = ((k & 0xFFFF) * 0x5BD1E995) + ((((k >> 16) * 0xE995) & 0xFFFF) << 16);
                k ^= k >> 24;
                k = ((k & 0xFFFF) * 0x5BD1E995) + ((((k >> 16) * 0xE995) & 0xFFFF) << 16);
                h = (((h & 0xFFFF) * 0x5BD1E995) + ((((h >> 16) * 0xE995) & 0xFFFF) << 16)) ^ k;
                l -= 4;
                i += 4;
            }

            switch (l)
            {
                case 3: h ^= (uint)(data[i + 2] << 16); goto case 2;
                case 2: h ^= (uint)(data[i + 1] << 8); goto case 1;
                case 1:
                    h ^= data[i];
                    h = ((h & 0xFFFF) * 0x5BD1E995) + ((((h >> 16) * 0xE995) & 0xFFFF) << 16);
                    break;
            }

            h ^= h >> 13;
            h = ((h & 0xFFFF) * 0x5BD1E995) + ((((h >> 16) * 0xE995) & 0xFFFF) << 16);
            h ^= h >> 15;
            return h;
        }
    }

    public static string CurseForge(byte[] data, int length, uint seed)
    {
        return Murmur2(data, length, seed).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
'@

try {
    if (-not ('OceanForensics' -as [type])) {
        Add-Type -TypeDefinition $script:ForensicsSource -Language CSharp -ErrorAction Stop
    }
}
catch {
    Write-Verbose "Entropy helper unavailable: $($_.Exception.Message)"
}

function Get-DataEntropy {
    param([byte[]]$Data)
    if (-not $Data -or $Data.Length -eq 0) { return 0.0 }
    if ('OceanForensics' -as [type]) {
        try { return [Math]::Round([OceanForensics]::Entropy($Data, $Data.Length), 3) } catch { }
    }
    $counts = New-Object 'int[]' 256
    foreach ($b in $Data) { $counts[$b]++ }
    $e = 0.0
    for ($i = 0; $i -lt 256; $i++) {
        if ($counts[$i] -eq 0) { continue }
        $p = [double]$counts[$i] / [double]$Data.Length
        $e -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($e, 3)
}

function Count-Fullwidth {
    param([string]$Text)
    if (-not $Text) { return 0 }
    if ('OceanForensics' -as [type]) {
        try { return [OceanForensics]::CountFullwidth($Text) } catch { }
    }
    return ([regex]::Matches($Text, '[\uFF01-\uFF5E\uFFE0-\uFFE6\u3000]')).Count
}

function Get-MinecraftRoots {
    param([string]$Extra)

    $candidates = @(
        @{ path = (Join-Path $env:APPDATA '.minecraft'); label = 'Minecraft'; depth = 0 },
        @{ path = (Join-Path $env:APPDATA 'minecraft'); label = 'Minecraft'; depth = 0 },
        @{ path = (Join-Path $env:APPDATA 'PrismLauncher\instances'); label = 'Prism'; depth = 4 },
        @{ path = (Join-Path $env:APPDATA 'com.modrinth.theseus\profiles'); label = 'Modrinth'; depth = 4 },
        @{ path = (Join-Path $env:APPDATA 'multimc\instances'); label = 'MultiMC'; depth = 4 },
        @{ path = (Join-Path $env:APPDATA 'gdlauncher_next\instances'); label = 'GDLauncher'; depth = 4 },
        @{ path = (Join-Path $env:APPDATA '.technic'); label = 'Technic'; depth = 4 },
        @{ path = (Join-Path $env:LOCALAPPDATA 'CurseForge\minecraft\Instances'); label = 'CurseForge'; depth = 4 },
        @{ path = (Join-Path $env:USERPROFILE 'curseforge\minecraft\Instances'); label = 'CurseForge'; depth = 4 },
        @{ path = (Join-Path $env:USERPROFILE '.lunarclient'); label = 'Lunar'; depth = 3 },
        @{ path = (Join-Path $env:APPDATA 'ATLauncher\instances'); label = 'ATLauncher'; depth = 4 }
    )

    if ($Extra) { $candidates += @{ path = $Extra; label = 'Custom'; depth = 0 } }

    # Loose drop locations: depth limited so a big Downloads tree cannot stall the scan.
    $candidates += @{ path = (Join-Path $env:USERPROFILE 'Downloads'); label = 'Downloads'; depth = 2 }
    $candidates += @{ path = (Join-Path $env:USERPROFILE 'Desktop'); label = 'Desktop'; depth = 2 }

    $roots = @()
    foreach ($c in $candidates) {
        try {
            if ($c.path -and (Test-Path -LiteralPath $c.path)) { $roots += $c }
        }
        catch { }
    }
    return $roots
}

function Read-ZipEntryBytes {
    param($Entry, [int]$MaxBytes = 131072)

    $stream = $null
    try {
        if ($null -eq $Entry -or $Entry.Length -le 0) { return , ([byte[]]@()) }
        $want = [int][Math]::Min([int64]$Entry.Length, [int64]$MaxBytes)
        if ($want -le 0) { return , ([byte[]]@()) }
        $stream = $Entry.Open()
        $buf = New-Object 'byte[]' $want
        $read = 0
        while ($read -lt $want) {
            $n = $stream.Read($buf, $read, $want - $read)
            if ($n -le 0) { break }
            $read += $n
        }
        if ($read -le 0) { return , ([byte[]]@()) }
        if ($read -lt $want) {
            $trimmed = New-Object 'byte[]' $read
            [Array]::Copy($buf, $trimmed, $read)
            return , $trimmed
        }
        return , $buf
    }
    catch { return , ([byte[]]@()) }
    finally { if ($stream) { $stream.Dispose() } }
}

function Get-JarFacts {
    param([Parameter(Mandatory)][string]$Path)

    $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $facts = [pscustomobject]@{
        path       = $fi.FullName
        name       = $fi.Name
        size       = [int64]$fi.Length
        modified   = ConvertTo-IsoTime $fi.LastWriteTime
        sha1       = ''
        sha256     = ''
        cf         = ''
        entries    = 0
        signatures = @()
        obfuscators = @()
        entropy    = 0.0
        fullwidth  = 0
        nested     = 0
        agent      = ''
        error      = ''
    }

    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            # One pass over the file produces every digest. Small files are held
            # in memory so the CurseForge fingerprint can be computed from the
            # same bytes; larger ones stream instead of allocating hundreds of MB.
            $len = [int64]$fi.Length
            if ($len -gt 0 -and $len -le 64MB) {
                $bytes = New-Object 'byte[]' $len
                $read = 0
                while ($read -lt $len) {
                    $n = $fs.Read($bytes, $read, [int]($len - $read))
                    if ($n -le 0) { break }
                    $read += $n
                }
                if ($read -eq $len) {
                    $h1 = [Security.Cryptography.SHA1]::Create()
                    $facts.sha1 = ([BitConverter]::ToString($h1.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
                    $h1.Dispose()
                    $h2 = [Security.Cryptography.SHA256]::Create()
                    $facts.sha256 = ([BitConverter]::ToString($h2.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
                    $h2.Dispose()
                    if ('OceanFingerprint' -as [type]) {
                        try { $facts.cf = [OceanFingerprint]::CurseForge($bytes, $len, 1) } catch { }
                    }
                }
            }
            else {
                $h1 = [Security.Cryptography.SHA1]::Create()
                $facts.sha1 = ([BitConverter]::ToString($h1.ComputeHash($fs))).Replace('-', '').ToLowerInvariant()
                $h1.Dispose()
                $fs.Position = 0
                $h2 = [Security.Cryptography.SHA256]::Create()
                $facts.sha256 = ([BitConverter]::ToString($h2.ComputeHash($fs))).Replace('-', '').ToLowerInvariant()
                $h2.Dispose()
            }
        }
        finally { $fs.Dispose() }
    }
    catch {
        $facts.error = 'hash unavailable'
    }

    $zip = $null
    try { $zip = [IO.Compression.ZipFile]::OpenRead($Path) }
    catch {
        if (-not $facts.error) { $facts.error = 'archive unreadable' }
        return $facts
    }

    try {
        $names = New-Object 'System.Collections.Generic.List[string]'
        $classEntries = New-Object 'System.Collections.Generic.List[object]'
        $manifest = $null
        $count = 0

        foreach ($entry in $zip.Entries) {
            $count++
            if ($count -gt 25000) { break }
            $entryName = $entry.FullName
            $names.Add($entryName)
            if ($entryName -match '(?i)\.jar$') { $facts.nested++ }
            if ($entryName -eq 'META-INF/MANIFEST.MF') { $manifest = $entry }
            elseif ($entryName -match '(?i)\.class$' -and $entry.Length -gt 2048) {
                if ($classEntries.Count -lt 3) { $classEntries.Add($entry) }
            }
        }
        $facts.entries = $count

        if ($names.Count -gt 0) {
            $blob = ($names -join "`n")
            $facts.fullwidth = Count-Fullwidth -Text $blob
            $lower = $blob.ToLowerInvariant()
            $sigList = New-Object 'System.Collections.Generic.List[string]'
            foreach ($sig in $script:JarSignatures.Keys) {
                if ($lower.Contains($sig)) {
                    $friendly = $script:JarSignatures[$sig]
                    if (-not $sigList.Contains($friendly)) { $sigList.Add($friendly) }
                }
            }
            $facts.signatures = $sigList.ToArray()

            # Obfuscator markers are only meaningful where they came from: an
            # archive entry name, never from arbitrary memory.
            $obfList = New-Object 'System.Collections.Generic.List[string]'
            foreach ($o in $script:ObfuscatorTokens) {
                if ($lower.Contains($o.ToLowerInvariant())) {
                    if (-not $obfList.Contains($o)) { $obfList.Add($o) }
                }
            }
            $facts.obfuscators = $obfList.ToArray()
        }

        if ($manifest) {
            $mBytes = Read-ZipEntryBytes -Entry $manifest -MaxBytes 16384
            if ($mBytes -and $mBytes.Length -gt 0) {
                $mText = [Text.Encoding]::UTF8.GetString($mBytes)
                if ($mText -match '(?im)^\s*(Premain-Class|Agent-Class)\s*:') {
                    $facts.agent = 'java agent manifest'
                }
            }
        }

        $samples = New-Object 'System.Collections.Generic.List[double]'
        foreach ($ce in $classEntries) {
            $bytes = Read-ZipEntryBytes -Entry $ce -MaxBytes 131072
            if ($bytes -and $bytes.Length -gt 1024) {
                $samples.Add((Get-DataEntropy -Data $bytes))
            }
        }
        if ($samples.Count -gt 0) {
            $facts.entropy = [Math]::Round((($samples | Measure-Object -Maximum).Maximum), 3)
        }
    }
    catch {
        if (-not $facts.error) { $facts.error = $_.Exception.Message }
    }
    finally {
        try { $zip.Dispose() } catch { }
    }

    return $facts
}

function Get-JarInventory {
    param(
        $Roots,
        [int]$MaxJars = 600,
        [int]$TimeoutSeconds = 90
    )

    $inventory = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $failed = 0

    foreach ($root in $Roots) {
        if ($inventory.Count -ge $MaxJars) { break }
        if ((Get-Date) -gt $deadline) { break }
        try {
            $params = @{
                LiteralPath    = $root.path
                Recurse        = $true
                Filter         = '*.jar'
                File           = $true
                Force          = $true
                ErrorAction    = 'SilentlyContinue'
            }
            if ($root.depth -and $root.depth -gt 0) { $params['Depth'] = $root.depth }
            $files = @(Get-ChildItem @params)
        }
        catch { continue }

        foreach ($f in $files) {
            if ($inventory.Count -ge $MaxJars) { break }
            if ((Get-Date) -gt $deadline) { break }
            if (-not $seen.Add($f.FullName)) { continue }
            if ($f.Length -gt 256MB) { $failed++; continue }
            try {
                $inventory.Add((Get-JarFacts -Path $f.FullName))
            }
            catch { $failed++ }
        }
    }

    Add-Provider -Name 'Jar Inventory' -Status 'ok' -Matched $inventory.Count `
        -Note ("{0} jar(s) parsed, {1} unreadable" -f $inventory.Count, $failed)
    Add-Activity -Label ("Jar inventory: {0} file(s) hashed" -f $inventory.Count) -Time (ConvertTo-IsoTime (Get-Date)) -Kind 'file'

    return $inventory
}

# ---------------------------------------------------------------------------
# 6b. Jar string analysis + Ocean bypass detections
# ---------------------------------------------------------------------------

function Get-JarStringIntel {
    <#
        Reads the actual contents of every jar: class files, json/toml/properties
        descriptors, scripts and payloads. Strings are extracted in native code and
        matched against the client markers, embedded URLs and encoded blob shapes.
    #>
    param(
        $Inventory,
        [int]$TimeoutSeconds = 70,
        [int]$MaxBytesPerJar = 3MB,
        [int]$MaxFilesPerJar = 160,
        [int]$MaxStringsPerJar = 2000
    )

    if (-not ('OceanStrings' -as [type])) {
        Add-Provider -Name 'Jar Strings' -Status 'blocked' -Note 'String interop unavailable'
        return
    }

    $jars = @()
    if ($null -ne $Inventory) {
        if ($Inventory -is [array]) { $jars = $Inventory } else { $jars = $Inventory.ToArray() }
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $scanned = 0
    $totalStrings = 0
    $extension = '(?i)\.(class|json|txt|toml|ya?ml|properties|cfg|conf|js|vbs|bat|ps1|sh|dat|mcmeta)$'

    foreach ($jar in $jars) {
        $stats = [pscustomobject]@{
            files     = 0
            strings   = 0
            cpClasses = 0
            hits      = @()
            urls      = @()
            blobs     = 0
            partial   = $false
            error     = ''
        }

        if ((Get-Date) -gt $deadline) { $stats.partial = $true; $jar | Add-Member -NotePropertyName stringIntel -NotePropertyValue $stats -Force; continue }

        $zip = $null
        try { $zip = [IO.Compression.ZipFile]::OpenRead($jar.path) }
        catch { $stats.error = 'archive unreadable'; $jar | Add-Member -NotePropertyName stringIntel -NotePropertyValue $stats -Force; continue }

        try {
            $byteBudget = 0
            $files = 0
            $stringsSeen = 0
            $hitList = New-Object 'System.Collections.Generic.List[string]'
            $urlList = New-Object 'System.Collections.Generic.List[string]'
            $blobs = 0

            foreach ($entry in $zip.Entries) {
                if ($files -ge $MaxFilesPerJar -or $byteBudget -ge $MaxBytesPerJar -or $stringsSeen -ge $MaxStringsPerJar) { $stats.partial = $true; break }
                if ((Get-Date) -gt $deadline) { $stats.partial = $true; break }
                if ($entry.Length -le 0 -or $entry.Length -gt 4MB) { continue }
                if ($entry.FullName -notmatch $extension) { continue }

                $data = Read-ZipEntryBytes -Entry $entry -MaxBytes 262144
                if (-not $data -or $data.Length -eq 0) { continue }

                $byteBudget += $data.Length
                $files++

                $extracted = @()
                $isClass = $entry.FullName -match '(?i)\.class$'

                if ($isClass -and ('OceanClassFile' -as [type])) {
                    # Parse the JVM constant pool instead of scanning raw bytes:
                    # the pool is where javac actually stores identifiers, and a
                    # raw scan desynchronises on long/double slots and modified
                    # UTF-8 (NUL encoded as C0 80).
                    try { $extracted = [OceanClassFile]::ExtractUtf8($data, 6, 3000) } catch { $extracted = @() }
                    if ($extracted.Count -gt 0) { $stats.cpClasses++ }
                }
                if (-not $extracted -or $extracted.Count -eq 0) {
                    try { $extracted = [OceanStrings]::Extract($data, $data.Length, 6, 1500) } catch { $extracted = @() }
                }

                # Fragment reassembly. A client that builds an identifier from
                # several short LDC constants leaves the pieces adjacent in the
                # pool - joining each run of short constants recovers the string.
                $scanSet = $extracted
                if ($isClass -and $extracted.Count -gt 1) {
                    $buf = New-Object 'System.Text.StringBuilder'
                    foreach ($s in $extracted) {
                        if ($s.Length -le 20 -and ($buf.Length + $s.Length) -le 240) {
                            [void]$buf.Append($s)
                        }
                        else {
                            if ($buf.Length -ge 8) { $scanSet += $buf.ToString() }
                            [void]$buf.Clear()
                            if ($s.Length -le 20) { [void]$buf.Append($s) }
                        }
                    }
                    if ($buf.Length -ge 8) { $scanSet += $buf.ToString() }
                }

                foreach ($s in $scanSet) {
                    $stringsSeen++
                    if ($stringsSeen -ge $MaxStringsPerJar) { break }

                    if ($hitList.Count -lt 40) {
                        foreach ($needle in $script:CheatStrings) {
                            if ($s.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                $record = "$needle :: $s"
                                if (-not $hitList.Contains($record)) { $hitList.Add($record) }
                                break
                            }
                        }
                    }

                    if ($urlList.Count -lt 12 -and $s -match '^https?://') {
                        $hostPart = ($s -replace '(?i)^https?://', '')
                        $hostPart = ($hostPart -split '/')[0]
                        if ($hostPart -and -not $urlList.Contains($hostPart)) { $urlList.Add($hostPart) }
                    }

                    if ($s.Length -ge 400 -and $s -match '^[A-Za-z0-9+/=]+$') { $blobs++ }
                }
            }

            $stats.files = $files
            $stats.strings = $stringsSeen
            $stats.hits = $hitList.ToArray()
            $stats.urls = $urlList.ToArray()
            $stats.blobs = $blobs
            $scanned++
            $totalStrings += $stringsSeen
        }
        catch { $stats.error = $_.Exception.Message }
        finally { try { $zip.Dispose() } catch { } }

        $jar | Add-Member -NotePropertyName stringIntel -NotePropertyValue $stats -Force
    }

    Add-Provider -Name 'Jar Strings' -Status 'ok' -Matched $scanned `
        -Note ("{0} jar(s) read, {1:N0} strings extracted" -f $scanned, $totalStrings)
}

function Resolve-JarStringFindings {
    param($Inventory, $Verified)

    $jars = @()
    if ($null -ne $Inventory) {
        if ($Inventory -is [array]) { $jars = $Inventory } else { $jars = $Inventory.ToArray() }
    }

    $flagged = 0
    foreach ($jar in $jars) {
        $intel = $jar.stringIntel
        if (-not $intel) { continue }
        if ($jar.sha1 -and $Verified -and $Verified.ContainsKey($jar.sha1)) { continue }

        $execState = Test-JarExecution -Jar $jar

        if (@($intel.hits).Count -gt 0) {
            $sample = (@($intel.hits) | Select-Object -First 3) -join ' | '
            if ($execState.inInstance) {
                Add-Finding -Category 'Cheater Records' -Title ("Client string in {0}" -f $jar.name) `
                    -Severity 'Detection' -Confirmed -Subject $jar.path -Tags @('In Instance') `
                    -Detail ("{0} (read from jar contents; {1})" -f (ConvertTo-SafeText $sample 260), $execState.reason) `
                    -Time $jar.modified
            }
            else {
                Add-Finding -Category 'Cheater Records' -Title ("Client string in {0}" -f $jar.name) `
                    -Severity 'Warning' -Subject $jar.path `
                    -Detail ("{0} (found in the archive, but no execution evidence links it to this session)" -f (ConvertTo-SafeText $sample 260)) `
                    -Time $jar.modified
            }
            $flagged++
        }

        $badUrls = @()
        foreach ($u in @($intel.urls)) {
            foreach ($d in $script:CheatDomains) {
                if ($u -match [regex]::Escape($d)) { $badUrls += $u; break }
            }
        }
        if ($badUrls.Count -gt 0) {
            if ($execState.inInstance) {
                Add-Finding -Category 'Suspicious logs' -Title ("Cheat endpoint in {0}" -f $jar.name) -Severity 'Detection' `
                    -Confirmed -Subject $jar.path -Tags @('In Instance') `
                    -Detail ("The jar references: {0}" -f ($badUrls -join ', ')) -Time $jar.modified
            }
            else {
                Add-Finding -Category 'Suspicious logs' -Title ("Cheat endpoint in {0}" -f $jar.name) -Severity 'Warning' `
                    -Subject $jar.path `
                    -Detail ("The jar references: {0}" -f ($badUrls -join ', ')) -Time $jar.modified
            }
            $flagged++
        }

        if ($intel.blobs -gt 0) {
            Add-Finding -Category 'Minecraft Mods' -Title ("Encoded payload in {0}" -f $jar.name) -Severity 'Warning' `
                -Detail ("{0} long base64 blob(s) inside the jar - typical of staged loaders." -f $intel.blobs) -Time $jar.modified
        }
    }

    if ($flagged -eq 0) {
        Add-Finding -Category 'Cheater Records' -Title 'Jar Contents Clean' -Severity 'Legit' `
            -Detail 'No client package, cheat domain or staged payload was found inside any indexed jar.'
    }
}

function Get-BypassArtefacts {
    $result = [pscustomobject]@{ virtualDisks = @(); importCode = @(); loaderWindows = 0 }

    # --- Bypass Method: VirtualDisk (Windows Sandbox / container VHDX) --------
    $containerRoot = Join-Path $env:ProgramData 'Microsoft\Windows\Containers\ContainerStorage'
    if (Test-Path -LiteralPath $containerRoot) {
        try {
            $disks = @(Get-ChildItem -LiteralPath $containerRoot -Recurse -Filter '*.vhdx' -File -Force -ErrorAction SilentlyContinue | Select-Object -First 5)
            foreach ($d in $disks) {
                $id = [IO.Path]::GetFileNameWithoutExtension($d.Name)
                $result.virtualDisks += [pscustomobject]@{ path = $d.FullName; id = $id; created = ConvertTo-IsoTime $d.CreationTime }
                Add-Finding -Category 'Bypass Methods' -Title "Bypass Method (VirtualDisk): $id" -Severity 'Detection' `
                    -Confirmed -Subject 'virtualdisk' -Tags @('Boot') `
                    -Detail ("Partition File: {0}  Virtual Disk: {1}  Creation Time: {2}" -f $d.FullName, $id, $d.CreationTime.ToString('yyyy-MM-dd HH:mm:ss.fffffff')) `
                    -Time (ConvertTo-IsoTime $d.CreationTime)
            }
        }
        catch { }
    }

    try {
        $vdisks = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop | Where-Object { $_.Model -match '(?i)virtual disk|vhd' })
        foreach ($vd in $vdisks) {
            $alreadySeen = $false
            foreach ($existing in $result.virtualDisks) { if ($existing.id -and $vd.SerialNumber -and $existing.id -eq $vd.SerialNumber) { $alreadySeen = $true } }
            if ($alreadySeen) { continue }
            $result.virtualDisks += [pscustomobject]@{ path = $vd.Model; id = [string]$vd.SerialNumber; created = '' }
            Add-Finding -Category 'Bypass Methods' -Title "Bypass Method (VirtualDisk): $($vd.Model)" -Severity 'Detection' `
                -Confirmed -Subject 'virtualdisk' -Tags @('Boot') `
                -Detail ("Mounted virtual disk: {0} (serial {1})." -f $vd.Model, $vd.SerialNumber)
        }
    }
    catch { }

    # --- Bypass Method: Fun Loader (external loader window) -------------------
    $loaderTokens = @(
        'fun loader', 'funloader', 'bypass', 'injector', 'auto clicker', 'auto-clicker',
        'autoclicker', 'vape', 'prestige', 'orchard', 'liquidbounce', 'wurst', 'meteor client'
    )
    $noise = '(?i)^(explorer|chrome|msedge|firefox|code|devenv|powershell|windowsterminal|searchapp|taskmgr|applicationframehost|startmenuexperiencehost)$'

    if ('OceanWindows' -as [type]) {
        try {
            $windows = @([OceanWindows]::List())
            foreach ($line in $windows) {
                $parts = $line -split "`t"
                if ($parts.Count -lt 3) { continue }
                $wpid = 0
                try { $wpid = [int]$parts[0] } catch { continue }
                $device = $parts[1]
                $title = $parts[2]

                $procName = ''
                try { $procName = (Get-Process -Id $wpid -ErrorAction Stop).ProcessName } catch { continue }
                if ($procName -match $noise) { continue }

                $blob = (($procName + ' ' + $title)).ToLowerInvariant()
                $matched = $false
                foreach ($t in $loaderTokens) { if ($blob.Contains($t)) { $matched = $true; break } }
                if (-not $matched) { continue }

                $result.loaderWindows++
                Add-Finding -Category 'Bypass Methods' -Title "Bypass Fun Loader: $wpid" -Severity 'Detection' `
                    -Confirmed -Subject 'funloader' -Tags @('In Instance') `
                    -Detail ("PID: {0} at {1} - window '{2}' ({3}.exe)" -f $wpid, $(if ($device) { $device } else { 'unknown display' }), (ConvertTo-SafeText $title 70), $procName)
            }
        }
        catch { }
    }

    return $result
}

function Resolve-CheatName {
    param([string]$Needle)
    if (-not $Needle) { return '' }
    $n = $Needle.ToLowerInvariant()

    # Compound needles that no single map key covers come first so that the
    # shorter 'zkm' key cannot win over the Prestige marker it is part of.
    if ($n -match 'zkm21') { return 'Prestige' }
    if ($n -match 'javaagent|bootclasspath') { return 'JVM Agent' }

    # Longest-key-first over the shared map so 'net/ccbluex/liquidbounce' wins
    # over any shorter token it happens to contain.
    $best = ''
    $bestLen = -1
    foreach ($key in $script:CheatNameMap.Keys) {
        $k = [string]$key
        if ($k.Length -le $bestLen) { continue }
        if ($n.Contains($k)) { $best = $script:CheatNameMap[$key]; $bestLen = $k.Length }
    }
    if ($best) { return $best }

    if ($n -match 'ccbluex') { return 'LiquidBounce' }
    if ($n -match 'meteor') { return 'Meteor' }

    return $Needle
}

function Resolve-JarFindings {
    param($Inventory, $Verified)

    $items = @()
    if ($null -ne $Inventory) {
        if ($Inventory -is [array]) { $items = $Inventory } else { $items = $Inventory.ToArray() }
    }

    if ($items.Count -eq 0) {
        Add-Finding -Category 'Minecraft Mods' -Title 'No Minecraft Jars Found' -Severity 'Warning' `
            -Detail 'No jar files were located in any known launcher directory.'
        return
    }

    $trusted = 0
    $flagged = 0

    foreach ($jar in $items) {
        $path = [string]$jar.path
        $inMods = $path -match '(?i)\\(mods|versions|gameDir)\\' -or $path -match '(?i)downloaded'
        $inLoose = $path -match '(?i)\\(downloads|desktop|temp)\\' 

        $isTrusted = $false
        if ($jar.sha1 -and $Verified -and $Verified.ContainsKey($jar.sha1)) {
            $isTrusted = $true
        }

        if ($isTrusted) {
            $src = $Verified[$jar.sha1]
            $trusted++
            $script:Whitelist[$jar.sha1] = "$($src.provider):$($src.label)"
            continue
        }

        # --- PRIMARY DIRECTIVE: execution, not existence --------------------
        $execState = Test-JarExecution -Jar $jar
        $clientNames = @($jar.signatures)
        $obfNames = @($jar.obfuscators)
        $isDualUse = $false
        $jarName = [string]$jar.name
        foreach ($du in $script:DualUseJars) { if ($jarName -match [regex]::Escape($du)) { $isDualUse = $true; break } }

        if ($clientNames.Count -gt 0) {
            $name = ($clientNames -join ', ')
            if ($execState.inInstance) {
                Add-Finding -Category 'Cheater Records' -Title ("{0} loaded in {1}" -f $name, $jar.name) `
                    -Severity 'Detection' -Confirmed -Subject $path -Tags @('In Instance') `
                    -Detail ("{0} - unverified jar contains {1} package(s) ({2:N1} KB) and is loaded into the running instance ({3})." -f $path, $name, ($jar.size / 1KB), $execState.reason) `
                    -Time $jar.modified
            }
            elseif ($execState.executed) {
                Add-Finding -Category 'Cheater Records' -Title ("{0} client in {1}" -f $name, $jar.name) `
                    -Severity 'Warning' -Subject $path -Tags @('Boot') `
                    -Detail ("{0} - unverified jar contains {1} package(s). It ran earlier this session ({2}), outside the live instance window." -f $path, $name, $execState.reason) `
                    -Time $jar.modified
            }
            else {
                Add-Finding -Category 'Cheater Records' -Title ("{0} archive present" -f $name) `
                    -Severity 'Warning' -Subject $path `
                    -Detail ("{0} contains {1} package(s) ({2:N1} KB) but no execution artefact exists for it - downloaded, never run. Not scored as a detection." -f $path, $name, ($jar.size / 1KB)) `
                    -Time $jar.modified
            }
            $flagged++
        }
        elseif ($isDualUse) {
            Add-Finding -Category 'Minecraft Mods' -Title ("Reverse-engineering tool: {0}" -f $jar.name) `
                -Severity 'Info' -Subject $path `
                -Detail ("{0} is a decompiler / bytecode editor. It legitimately references obfuscator names, so it is context rather than evidence." -f $path) `
                -Time $jar.modified
        }
        elseif ($obfNames.Count -gt 0) {
            $name = ($obfNames -join ', ')
            Add-Finding -Category 'Minecraft Mods' -Title ("Obfuscator marker in {0}" -f $jar.name) `
                -Severity 'Warning' -Subject $path `
                -Detail ("{0} matches obfuscator signature(s): {1}." -f $path, $name) -Time $jar.modified
            $flagged++
        }

        if ($inLoose -and $jar.size -gt 100KB) {
            Add-Finding -Category 'Minecraft Mods' -Title ("Jar Outside Launcher Directory: {0}" -f $jar.name) `
                -Severity 'Warning' -Subject $path `
                -Detail ("{0} - a large archive sitting loose in a drop folder. No execution proof, so this is context, not a detection." -f $path) `
                -Time $jar.modified
            $flagged++
        }

        if ($jar.entropy -ge 7.2) {
            Add-Finding -Category 'Minecraft Mods' -Title ("Packed class data [{0}]" -f $jar.name) -Severity 'Warning' `
                -Subject $path `
                -Detail ("Class-file entropy is {0}/8.0 - compiled-and-obfuscated, not a normal mod. Path: {1}" -f $jar.entropy, $path) `
                -Time $jar.modified
            $flagged++
        }

        if ($jar.fullwidth -gt 0) {
            Add-Finding -Category 'Minecraft Mods' -Title ("Fullwidth Unicode in {0}" -f $jar.name) -Severity 'Warning' `
                -Subject $path `
                -Detail ("{0} fullwidth character(s) inside {1} - a filter-evasion technique used by obfuscators." -f $jar.fullwidth, $jar.name) `
                -Time $jar.modified
            $flagged++
        }

        if ($jar.nested -gt 0) {
            Add-Finding -Category 'Minecraft Mods' -Title ("Nested Jars in {0}" -f $jar.name) -Severity 'Warning' `
                -Subject $path `
                -Detail ("{0} contains {1} embedded jar(s); payloads are usually staged this way." -f $jar.name, $jar.nested) `
                -Time $jar.modified
        }

        if ($jar.agent) {
            Add-Finding -Category 'Cheater Records' -Title ("Java Agent Manifest: {0}" -f $jar.name) -Severity 'Warning' `
                -Subject $path -Tags @('In Instance') `
                -Detail ("{0} declares a Premain/Agent class - it loads before Minecraft main." -f $jar.name) `
                -Time $jar.modified
        }
    }

    $total = $items.Count
    Add-Finding -Category 'Minecraft Mods' -Title ("Jar Review Complete [{0} files]" -f $total) -Severity 'Info' `
        -Detail ("{0} hash-verified, {1} flagged, {2} clean." -f $trusted, $flagged, [Math]::Max(0, $total - $trusted - $flagged))
}

# ---------------------------------------------------------------------------
# 7. Phase 5 - memory scan (read-only, javaw.exe + explorer.exe)
# ---------------------------------------------------------------------------

function Invoke-MemoryScan {
    param(
        [string[]]$Needles = $script:CheatStrings,
        [int]$TimeoutMs = 20000,
        [int]$MaxTotalMB = 320,
        [long]$MaxRegionMB = 512
    )

    if (-not ('OceanMemScan' -as [type])) {
        Add-Provider -Name 'Memory' -Status 'blocked' -Note 'ReadProcessMemory interop failed to compile'
        Add-Finding -Category 'Suspicious logs' -Title 'Memory Scan Unavailable' -Severity 'Warning' `
            -Detail 'The native interop layer could not be initialised; resident strings were not checked.'
        return
    }

    $targets = @(
        @{ proc = 'javaw'; label = 'javaw.exe'; tag = 'In Instance'; timeout = $TimeoutMs; mb = $MaxTotalMB },
        @{ proc = 'explorer'; label = 'explorer.exe'; tag = ''; timeout = 12000; mb = 120 }
    )

    $scannedAny = $false
    foreach ($target in $targets) {
        $procs = @(Get-Process -Name $target.proc -ErrorAction SilentlyContinue)
        if ($procs.Count -eq 0) { continue }
        $p = $procs | Sort-Object WorkingSet64 -Descending | Select-Object -First 1

        Write-Phase -Activity 'Reading process memory' -Percent 78 -Status "$($target.label) (pid $($p.Id))"

        try {
            $raw = [OceanMemScan]::Scan($p.Id, $Needles, ([int64]$target.mb * 1MB), ([int64]$MaxRegionMB * 1MB), [int]$target.timeout)
        }
        catch {
            Add-Finding -Category 'Suspicious logs' -Title "Memory Scan Failed: $($target.label)" -Severity 'Warning' `
                -Detail $_.Exception.Message
            continue
        }

        $scannedAny = $true
        $bytesRead = [int64]0
        $timedOut = $false
        $win32 = $null
        $hits = New-Object 'System.Collections.Generic.List[object]'

        foreach ($line in @($raw)) {
            if (-not $line) { continue }
            if ($line.StartsWith('!ERROR')) {
                $parts = $line -split "`t"
                if ($parts.Count -ge 2) { $win32 = $parts[1] }
                continue
            }
            if ($line.StartsWith('!STATS')) {
                $parts = $line -split "`t"
                if ($parts.Count -ge 2) { $bytesRead = [int64]$parts[1] }
                continue
            }
            if ($line -eq '!TIMEOUT') { $timedOut = $true; continue }
            if ($line.StartsWith('!')) { continue }

            $parts = $line -split "`t"
            if ($parts.Count -lt 2) { continue }
            $hits.Add([pscustomobject]@{
                    needle = $parts[0]
                    count  = [int]$parts[1]
                    target = $target.label
                })
        }

        if ($win32) {
            Add-Finding -Category 'Suspicious logs' -Title "Memory Access Denied: $($target.label)" -Severity 'Warning' `
                -Detail "OpenProcess failed (Win32 error $win32). Run the tool elevated to read the process."
            continue
        }

        Add-Provider -Name ("Memory: $($target.label)") -Status 'ok' -Matched $hits.Count `
            -Note ("{0:N0} MB read{1}" -f ($bytesRead / 1MB), $(if ($timedOut) { ' (time budget hit)' } else { '' }))

        if ($timedOut) {
            Add-Finding -Category 'Suspicious logs' -Title 'Memory Scan Truncated' -Severity 'Info' `
                -Detail ("$($target.label) memory is larger than the time budget; {0:N0} MB were inspected." -f ($bytesRead / 1MB))
        }

        foreach ($hit in $hits) {
            $friendly = Resolve-CheatName -Needle $hit.needle
            [void]$script:MemoryHits.Add($friendly)
            [void]$script:MemoryHits.Add($hit.needle)

            $sev = 'Warning'
            $confirmed = $false
            if ($hit.needle -match 'javaagent|bootclasspath') {
                $sev = 'Info'
            }
            elseif ($target.tag -eq 'In Instance') {
                # A client string resident inside javaw.exe can only get there
                # if that client was loaded - this is the strongest signal we
                # have and it is never a heuristic.
                $sev = 'Detection'
                $confirmed = $true
            }

            $tags = @()
            if ($target.tag) { $tags += $target.tag }
            Add-Finding -Category 'Suspicious logs' -Title ("{0} string in {1}" -f $friendly, $hit.target) -Severity $sev `
                -Confirmed:$confirmed -Subject $friendly -Tags $tags `
                -Detail ("Matched '{0}' in {1:N0} readable region(s).{2}" -f $hit.needle, $hit.count, `
                    $(if ($confirmed) { ' This string can only be resident if the client is loaded.' } else { ' Seen outside the game process - treat as context, not proof.' }))
        }

        if ($hits.Count -eq 0) {
            Add-Finding -Category 'Suspicious logs' -Title ("No Cheat Strings: $($target.label)") -Severity 'Legit' `
                -Detail ("{0:N0} MB of committed, readable memory matched none of the {1} client signatures." -f ($bytesRead / 1MB), $Needles.Count)
        }
    }

    if (-not $scannedAny) {
        Add-Provider -Name 'Memory' -Status 'skipped' -Note 'No javaw.exe / explorer.exe mapped'
    }
}

# ---------------------------------------------------------------------------
# 8. Phase 6 - JVM flags, native modules, ports, process intel
# ---------------------------------------------------------------------------

function Get-JavaArtifacts {
    param([int]$GamePid)

    $found = [pscustomobject]@{ flags = @(); agents = @(); dlls = @(); ports = @() }

    $procs = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -ErrorAction SilentlyContinue)
    if ($GamePid -gt 0) {
        $procs = @($procs | Where-Object { $_.ProcessId -eq $GamePid })
    }
    else {
        $procs = @()
    }

    if ($procs.Count -eq 0) {
        Add-Provider -Name 'JVM Flags' -Status 'skipped' -Note 'No Minecraft JVM identified'
        return $found
    }

    foreach ($p in $procs) {
        $cmd = [string](Get-SafeProperty $p 'CommandLine' '')
        if (-not $cmd) { continue }

        if ($cmd -match '-javaagent:(?:\"([^\"]+)\"|([^\s]+))') {
            $agentPath = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
            $found.agents += $agentPath
            $exists = $false
            try { $exists = Test-Path -LiteralPath $agentPath } catch { }
            Add-Finding -Category 'Java Connections' -Title 'JVM -javaagent Loaded' -Severity 'Detection' `
                -Confirmed -Subject 'jvm-agent' -Tags @('In Instance') `
                -Detail ("javaw.exe (pid {0}) was started with a bytecode agent: {1}{2}" -f $p.ProcessId, $agentPath, $(if ($exists) { '' } else { ' (file no longer present)' }))
        }

        if ($cmd -match '-Xbootclasspath') {
            $found.flags += '-Xbootclasspath'
            Add-Finding -Category 'Java Connections' -Title 'JVM -Xbootclasspath Override' -Severity 'Detection' `
                -Confirmed -Subject 'jvm-agent' -Tags @('In Instance') `
                -Detail 'The bootstrap class loader was redirected - a classic way to replace Minecraft classes before launch.'
        }

        if ($cmd -match '-XX:\+DisableAttachMechanism') {
            $found.flags += '-XX:+DisableAttachMechanism'
            Add-Finding -Category 'Java Connections' -Title 'Attach Mechanism Disabled' -Severity 'Warning' `
                -Detail 'The JVM was started with the agent attach mechanism disabled, blocking live inspection.'
        }

        if ($cmd -match '(?i)(cheat|inject|client\.jar|vape|prestige)') {
            $found.flags += 'suspicious argument'
            Add-Finding -Category 'Java Connections' -Title 'Suspicious JVM Argument' -Severity 'Warning' `
                -Detail (ConvertTo-SafeText $cmd 260)
        }
    }

    # --- Native modules inside javaw.exe ------------------------------------
    if ($GamePid -gt 0) {
        $proc = Get-Process -Id $GamePid -ErrorAction SilentlyContinue
        $modules = @()
        try { $modules = @($proc.Modules) } catch { $modules = @() }

        foreach ($m in $modules) {
            $mp = [string]$m.FileName
            if (-not $mp) { continue }
            if ($mp -match '(?i)\\windows\\') { continue }
            if ($mp -match '(?i)\\(libraries|versions|runtime|jdk|jre|bin)\\') { continue }
            if ($mp -match '(?i)\\java\\') { continue }

            $sig = $null
            try { $sig = Get-AuthenticodeSignature -LiteralPath $mp -ErrorAction Stop } catch { }
            $status = if ($sig) { [string]$sig.Status } else { 'Unknown' }
            if ($status -eq 'Valid') { continue }

            $subject = ''
            try { if ($sig -and $sig.SignerCertificate) { $subject = [string]$sig.SignerCertificate.Subject } } catch { }
            foreach ($trusted in $script:TrustedSigners) {
                if ($subject -and $subject -match [regex]::Escape($trusted)) { $status = 'Valid'; break }
            }
            if ($status -eq 'Valid') { continue }

            $isHostile = $mp -match '(?i)\\(temp|downloads|desktop|appdata\\roaming\\[a-z0-9]{1,3})\\'

            # HashMismatch means the binary changed AFTER it was signed - that is
            # tampering, not an installer choice. Anything else unsigned needs a
            # hostile path to become a Detection.
            $sev = 'Warning'
            $confirmed = $false
            if ($status -eq 'HashMismatch') { $sev = 'Detection'; $confirmed = $true }
            elseif ($isHostile -and $status -in @('NotSigned', 'UnknownError', 'NotTrusted')) { $sev = 'Detection'; $confirmed = $true }

            $found.dlls += [pscustomobject]@{ path = $mp; status = $status }
            Add-Finding -Category 'Java Connections' -Title ("Unsigned Module: {0}" -f (Split-Path -Leaf $mp)) -Severity $sev `
                -Confirmed:$confirmed -Subject $mp -Tags @('In Instance') `
                -Detail ("{0} is mapped into javaw.exe and its signature status is '{1}'. Path: {2}" -f (Split-Path -Leaf $mp), $status, $mp)
        }
    }

    # --- Prestige's loopback port ------------------------------------------
    $conns = @()
    try { $conns = @(Get-NetTCPConnection -LocalPort 42385 -ErrorAction Stop) } catch { $conns = @() }
    if ($conns.Count -gt 0) {
        $found.ports += 42385
        $owners = ($conns | Select-Object -ExpandProperty OwningProcess -Unique) -join ', '
        Add-Finding -Category 'Cheater Records' -Title 'Prestige Port 42385 Active' -Severity 'Detection' `
            -Confirmed -Subject 'prestige' -Tags @('In Instance') `
            -Detail "A listener/connection on the Prestige client port exists (pid: $owners)."
    }

    Add-Provider -Name 'JVM Flags' -Status 'ok' -Matched $found.flags.Count -Note "$($procs.Count) java process(es)"
    return $found
}

function Get-ProcessIntel {
    $result = [pscustomobject]@{ cheat = @(); recording = @(); history = @() }

    foreach ($name in $script:CheatProcesses) {
        $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
        foreach ($p in $procs) {
            $result.cheat += $p.ProcessName
            Add-Finding -Category 'Cheater Records' -Title ("Live Process: {0}.exe" -f $p.ProcessName) -Severity 'Detection' `
                -Confirmed -Subject $p.ProcessName -Tags @('In Instance') `
                -Detail "Process id $($p.Id) was running during the scan."
        }
    }

    foreach ($name in $script:DualUseProcesses) {
        $p = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p) {
            Add-Finding -Category 'Cheater Records' -Title ("Dual-Use Tool Running: {0}.exe" -f $p.ProcessName) -Severity 'Warning' `
                -Subject $p.ProcessName -Tags @('In Instance') `
                -Detail 'Debugging/inspection tooling was running during the session. Ask why it was open.'
        }
    }

    $recorders = @('obs64', 'obs32', 'obs', 'medal', 'streamlabs', 'bandicam', 'fraps', 'action', 'camtasia', 'sharex', 'medal.tv')
    foreach ($name in $recorders) {
        $p = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p) {
            $result.recording += $p.ProcessName
            Add-Finding -Category 'Recording Software' -Title ("Recording: {0}.exe" -f $p.ProcessName) -Severity 'Info' `
                -Detail 'A screen recorder is running; ask for the raw session recording.'
        }
    }

    $historyPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path -LiteralPath $historyPath) {
        try {
            $lines = @(Get-Content -LiteralPath $historyPath -Tail 800 -ErrorAction Stop)
            foreach ($line in $lines) {
                foreach ($t in $script:CheatTokens) {
                    if ($line -match [regex]::Escape($t)) {
                        $safe = ConvertTo-SafeText $line 150
                        if (-not $result.history.Contains($safe)) {
                            $result.history += $safe
                            Add-Finding -Category 'Suspicious logs' -Title 'PowerShell History Match' -Severity 'Warning' -Detail $safe
                        }
                        break
                    }
                }
            }
            Add-Provider -Name 'PowerShell History' -Status 'ok' -Matched $result.history.Count -Note "$($lines.Count) recent commands"
        }
        catch { }
    }

    return $result
}

# ---------------------------------------------------------------------------
# 9. Boot sequence + verdict + report model
# ---------------------------------------------------------------------------

function Get-BootSequence {
    param($SystemInfo)

    $boot = [ordered]@{
        biosVendor         = ''
        biosVersion        = ''
        biosDate           = ''
        boardProduct       = ''
        boardManufacturer  = ''
        secureBoot         = $null
        fastStartup        = $null
        bootTime           = ''
        uptimeMinutes      = 0
        anomalies          = @()
        entries            = @()
    }

    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $boot.biosVendor = ConvertTo-SafeText (Get-SafeProperty $bios 'Manufacturer' '')
        $boot.biosVersion = ConvertTo-SafeText (Get-SafeProperty $bios 'SMBIOSBIOSVersion' '')
        $rel = Get-SafeProperty $bios 'ReleaseDate' $null
        if ($rel) { $boot.biosDate = ([datetime]$rel).ToString('yyyy-MM-dd') }
    }
    catch { }

    try {
        $board = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop
        $boot.boardProduct = ConvertTo-SafeText (Get-SafeProperty $board 'Product' '')
        $boot.boardManufacturer = ConvertTo-SafeText (Get-SafeProperty $board 'Manufacturer' '')
    }
    catch { }

    try {
        $sb = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop
        if ($null -ne $sb.UEFISecureBootEnabled) { $boot.secureBoot = [bool]($sb.UEFISecureBootEnabled -eq 1) }
    }
    catch { }

    try {
        $pm = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction Stop
        if ($null -ne $pm.HiberbootEnabled) { $boot.fastStartup = [bool]($pm.HiberbootEnabled -eq 1) }
    }
    catch { }

    $boot.bootTime = $SystemInfo.bootTime
    $boot.uptimeMinutes = $SystemInfo.uptimeMinutes

    $anomalies = New-Object 'System.Collections.Generic.List[string]'

    if ($boot.secureBoot -eq $false) {
        $anomalies.Add('[SUSPICIOUS] Secure Boot is disabled in firmware')
        Add-Finding -Category 'Boot Sequence' -Title 'Secure Boot Disabled' -Severity 'Warning' -Tags @('Boot') `
            -Detail 'Firmware reports UEFI Secure Boot off, so an unsigned bootkit cannot be ruled out by measurement.'
    }
    elseif ($boot.secureBoot -eq $true) {
        Add-Finding -Category 'Boot Sequence' -Title 'Secure Boot Enabled' -Severity 'Legit' -Tags @('Boot') `
            -Detail 'UEFI Secure Boot is on - the boot chain is measured by firmware.'
    }

    if ($boot.fastStartup -eq $true) {
        $anomalies.Add('[SUSPICIOUS] Fast startup (hiberboot) enabled - boot time is a resume')
        Add-Finding -Category 'Boot Sequence' -Title 'Fast Startup Enabled' -Severity 'Warning' -Tags @('Boot') `
            -Detail 'HiberbootEnabled=1: LastBootUpTime can reflect a hibernation resume, not a cold boot.'
    }

    if ($SystemInfo.uptimeMinutes -gt 0 -and $SystemInfo.uptimeMinutes -lt 10) {
        $anomalies.Add('[SUSPICIOUS] Uptime under 10 minutes before the scan')
    }

    $boot.anomalies = $anomalies.ToArray()
    $boot.entries = @(
        [pscustomobject]@{ name = 'Windows Boot Manager'; detail = 'BCD default entry'; kind = 'System' },
        [pscustomobject]@{ name = 'Current OS Loader'; detail = $SystemInfo.osName; kind = 'Windows' }
    )

    Add-Provider -Name 'Boot Sequence' -Status 'ok' -Matched $anomalies.Count -Note "$($anomalies.Count) anomaly(ies)"
    Add-Activity -Label 'System boot recorded' -Time $SystemInfo.bootTime -Kind 'boot'
    if ($SystemInfo.gameStart) {
        Add-Activity -Label 'Minecraft JVM observed' -Time $SystemInfo.gameStart -Kind 'game'
    }
    if ($SystemInfo.recycleLatest) {
        Add-Activity -Label ("Recycle bin: {0} item(s)" -f $SystemInfo.recycleCount) -Time $SystemInfo.recycleLatest -Kind 'recycle'
    }

    return [pscustomobject]$boot
}

function Get-Verdict {
    param($Findings)

    $detections = @($Findings | Where-Object { $_.severity -eq 'Detection' })
    $warnings = @($Findings | Where-Object { $_.severity -eq 'Warning' })
    $legit = @($Findings | Where-Object { $_.severity -eq 'Legit' })

    # Distinct evidence SOURCES matter more than raw counts: ten rows produced
    # by one heuristic are still one observation, while memory + registry +
    # execution together are three independent ones.
    $sources = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $detections) { [void]$sources.Add([string]$f.category) }

    $confirmed = @($detections | Where-Object { $_.confirmed })
    $heuristic = [Math]::Max(0, $detections.Count - $confirmed.Count)

    # Warnings alone can never produce a cheating verdict: only proven detections
    # carry enough weight, which keeps environmental noise (no elevation, VPN,
    # unsigned LWJGL natives) from condemning a clean player.
    $warningScore = [Math]::Min(24, ($warnings.Count * 1.5))
    $score = ($confirmed.Count * 22) + ($heuristic * 8) + $warningScore
    $score = [int][Math]::Round([Math]::Min(100, [Math]::Max(0, $score)))

    $label = 'LEGIT'
    if (($confirmed.Count -ge 2 -and $sources.Count -ge 2) -or ($detections.Count -ge 3 -and $score -ge 70)) {
        $label = 'CHEATING'
    }
    elseif ($detections.Count -ge 1 -or $score -ge 30) {
        $label = 'SUSPICIOUS'
    }

    return [pscustomobject]@{
        label      = $label
        score      = $score
        detections = $detections.Count
        warnings   = $warnings.Count
        legit      = $legit.Count
        confirmed  = $confirmed.Count
        heuristic  = $heuristic
        sources    = $sources.Count
        downgraded = [int]$script:Downgraded
    }
}

function New-Report {
    param($SystemInfo, $Boot, $Verdict, $JarInventory, $JavaArtifacts, $Prefetch, $Dns, $ProcessIntel)

    $finished = Get-Date
    $duration = [int]([Math]::Max(1, ($finished - $script:StartedAt).TotalSeconds))

    $jarList = @()
    $jarSource = @()
    if ($null -ne $JarInventory) {
        if ($JarInventory -is [array]) { $jarSource = $JarInventory } else { $jarSource = $JarInventory.ToArray() }
    }
    foreach ($j in $jarSource) {
        if (-not $j) { continue }
        $jarList += [pscustomobject]@{
            name     = $j.name
            path     = $j.path
            size     = $j.size
            modified = $j.modified
            sha1     = $j.sha1
            entries  = $j.entries
            entropy  = $j.entropy
            verified = [bool]($script:Whitelist.ContainsKey($j.sha1))
            source   = if ($script:Whitelist.ContainsKey($j.sha1)) { $script:Whitelist[$j.sha1] } else { '' }
            error    = $j.error
        }
    }

    return [pscustomobject]@{
        meta       = [pscustomobject]@{
            pin             = $script:PIN
            startedAt       = (ConvertTo-IsoTime $script:StartedAt)
            finishedAt      = (ConvertTo-IsoTime $finished)
            durationSeconds = $duration
            host            = $SystemInfo.hostname
            user            = $SystemInfo.username
            version         = $script:ToolVersion
            elevated        = [bool](Test-IsAdmin)
            downgraded      = [int]$script:Downgraded
            verified        = $script:Whitelist.Count
        }
        verdict    = $Verdict
        system     = [pscustomobject]@{
            os           = ("{0} {1}" -f $SystemInfo.osName, $SystemInfo.osEdition).Trim()
            build        = $SystemInfo.osBuild
            bootTime     = $SystemInfo.bootTime
            uptimeMinutes = $SystemInfo.uptimeMinutes
            vpn          = $SystemInfo.vpn
            vpnDetail    = $SystemInfo.vpnDetail
            recycleCount = $SystemInfo.recycleCount
            recycleSize  = $SystemInfo.recycleSize
            recycleLatest = $SystemInfo.recycleLatest
            installDate  = $SystemInfo.installDate
            country      = $SystemInfo.country
            game         = $SystemInfo.gameName
            gameStart    = $SystemInfo.gameStart
            gameRunning  = $SystemInfo.gameRunning
            gamePid      = $SystemInfo.gamePid
            gameMemoryMB = $SystemInfo.gameMemoryMB
            windowText   = $SystemInfo.windowText
            cpu          = $SystemInfo.cpu
            gpu          = $SystemInfo.gpu
            ram          = $SystemInfo.ram
            hostname     = $SystemInfo.hostname
            user         = $SystemInfo.username
        }
        boot       = $Boot
        findings   = $script:Findings.ToArray()
        activity   = $script:Activity.ToArray()
        providers  = $script:Providers.ToArray()
        jars       = $jarList
        prefetch   = [pscustomobject]@{
            total        = $Prefetch.total
            available    = $Prefetch.available
            newest       = $Prefetch.newestWrite
            missingBaseline = @($Prefetch.missingBaseline)
        }
        dns        = [pscustomobject]@{ total = $Dns.total; hits = @($Dns.hits) }
        java       = [pscustomobject]@{
            agents   = @($JavaArtifacts.agents)
            dlls     = @($JavaArtifacts.dlls)
            ports    = @($JavaArtifacts.ports)
        }
        intel      = [pscustomobject]@{
            cheatProcesses = @($ProcessIntel.cheat)
            recording      = @($ProcessIntel.recording)
            history        = @($ProcessIntel.history)
        }
    }
}

# ---------------------------------------------------------------------------
# 10. Dashboard markup (Ocean replica)
# ---------------------------------------------------------------------------

$script:DashboardHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="color-scheme" content="dark" />
<title>Ocean Anti-Cheat - Scan Results</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230a0a0a'/%3E%3Ctext x='16' y='22' font-family='monospace' font-size='15' fill='%23ff3333' text-anchor='middle'%3E(*%3E%3C/text%3E%3C/svg%3E" />
<style>
/* ---------------------------------------------------------------- tokens */
:root{
  --bg:#0a0a0a; --bg2:#0d0d0e; --side:#080809;
  --card:#121212; --card2:#161618; --card3:#1b1b1e;
  --line:#232326; --line2:#2e2e33;
  --txt:#f3f3f5; --txt2:#c9c9d1; --muted:#8a8a94; --muted2:#5e5e68;
  --red:#ff3333; --red2:#ff6b6b; --red-dim:#3a1414; --red-bg:rgba(255,51,51,.10);
  --yellow:#ffb020; --yellow-bg:rgba(255,176,32,.10);
  --green:#2fd574; --green-bg:rgba(47,213,116,.10);
  --blue:#5b9dff; --purple:#a97bff;
  --r:14px; --r2:10px;
  --shadow:0 18px 40px -24px rgba(0,0,0,.9);
  --mono:'Cascadia Mono','SF Mono',Consolas,'Roboto Mono',monospace;
  --sans:'Inter','Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,sans-serif;
}
*,*::before,*::after{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;background:var(--bg);color:var(--txt);font-family:var(--sans);
  font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased;
  letter-spacing:.1px;
  background-image:
    radial-gradient(900px 500px at 78% -12%,rgba(255,51,51,.10),transparent 60%),
    radial-gradient(700px 480px at 6% 105%,rgba(91,157,255,.06),transparent 62%);
  background-attachment:fixed;
}
::selection{background:rgba(255,51,51,.30)}
::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-thumb{background:#212126;border-radius:9px;border:3px solid var(--bg)}
::-webkit-scrollbar-thumb:hover{background:#2e2e34}
::-webkit-scrollbar-track{background:transparent}
a{color:inherit;text-decoration:none}
button{font:inherit;color:inherit;background:none;border:0;cursor:pointer}
kbd{
  font-family:var(--mono);font-size:10px;padding:1px 5px;border-radius:5px;
  background:#1e1e22;border:1px solid var(--line2);color:var(--muted2);
}
svg{display:block}
::-webkit-scrollbar{scrollbar-width:thin;scrollbar-color:#212126 transparent}

/* ---------------------------------------------------------------- layout */
.app{display:flex;min-height:100vh}
.sidebar{
  width:236px;flex:0 0 236px;background:linear-gradient(180deg,#080809,#0a0a0c 60%,#08080a);
  border-right:1px solid var(--line);display:flex;flex-direction:column;
  position:sticky;top:0;height:100vh;overflow-y:auto;z-index:30;
}
.main{flex:1;min-width:0;display:flex;flex-direction:column}

/* ---------------------------------------------------------------- sidebar */
.brand{display:flex;gap:11px;align-items:center;padding:18px 16px 16px;border-bottom:1px solid var(--line)}
.brand .mark{
  width:34px;height:34px;border-radius:9px;display:grid;place-items:center;
  background:#101014;border:1px solid var(--line2);
  font-family:var(--mono);font-size:13px;color:#fff;
  box-shadow:0 0 0 1px rgba(255,51,51,.16),0 0 18px -6px rgba(255,51,51,.55);
}
.brand .mark span{color:var(--red)}
.brand .nm{font-size:15px;font-weight:650;letter-spacing:.2px}
.brand .sub{font-size:10.5px;color:var(--muted2);font-family:var(--mono);margin-top:1px}

.nav{padding:14px 10px;flex:1}
.nav h4{
  margin:16px 8px 7px;font-size:9.5px;letter-spacing:.16em;color:var(--muted2);
  font-weight:650;display:flex;align-items:center;justify-content:space-between;
}
.nav h4:first-child{margin-top:2px}
.nav h4 .chev{transition:transform .2s ease;opacity:.6}
.nav h4.collapsed .chev{transform:rotate(-90deg)}
.nav ul{list-style:none;margin:0;padding:0}
.nav li a{
  display:flex;align-items:center;gap:9px;padding:7.5px 9px;border-radius:9px;
  color:var(--txt2);font-size:12.5px;transition:background .14s ease,color .14s ease,transform .14s ease;
  position:relative;
}
.nav li a:hover{background:#141417;color:#fff;transform:translateX(2px)}
.nav li a.on{
  background:linear-gradient(90deg,rgba(255,51,51,.16),rgba(255,51,51,.03));
  color:#fff;box-shadow:inset 0 0 0 1px rgba(255,51,51,.30);
}
.nav li a.on::before{
  content:'';position:absolute;left:-10px;top:50%;transform:translateY(-50%);
  width:3px;height:18px;border-radius:0 3px 3px 0;background:var(--red);
  box-shadow:0 0 12px var(--red);
}
.nav li a .ico{width:15px;height:15px;flex:0 0 15px;opacity:.85}
.nav li a.on .ico{opacity:1;color:var(--red)}
.nav li a .dot{width:6px;height:6px;border-radius:50%;background:var(--red);margin-left:auto;box-shadow:0 0 8px var(--red)}
.nav li a .cnt{margin-left:auto;font-size:10px;font-family:var(--mono);color:var(--muted2);background:#141417;padding:1px 6px;border-radius:6px}
.nav .sublist{padding-left:14px}
.nav .sublist a{font-size:12px;padding:6px 9px}
.side-foot{padding:12px 14px 16px;border-top:1px solid var(--line);font-size:11px;color:var(--muted2)}
.side-foot .row{display:flex;align-items:center;gap:7px;padding:5px 0}
.pulse{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 0 0 rgba(47,213,116,.6);animation:pulse 2.2s infinite}
@keyframes pulse{70%{box-shadow:0 0 0 7px rgba(47,213,116,0)}100%{box-shadow:0 0 0 0 rgba(47,213,116,0)}}

/* ---------------------------------------------------------------- topbar */
.topbar{
  height:52px;display:flex;align-items:center;gap:16px;padding:0 20px;
  background:rgba(10,10,11,.82);backdrop-filter:blur(14px);
  border-bottom:1px solid var(--line);position:sticky;top:0;z-index:25;
}
.crumb{display:flex;align-items:center;gap:7px;font-size:12.5px;color:var(--muted);min-width:0}
.crumb .sep{opacity:.4}
.crumb b{color:var(--txt);font-weight:600}
.crumb .cur{
  font-family:var(--mono);font-size:11.5px;color:#fff;background:#17171a;
  border:1px solid var(--line2);padding:2px 8px;border-radius:7px;
}
.search{
  margin-left:auto;display:flex;align-items:center;gap:8px;min-width:250px;
  background:#111114;border:1px solid var(--line);border-radius:10px;padding:6px 10px;
  transition:border-color .16s ease,box-shadow .16s ease;
}
.search:focus-within{border-color:rgba(255,51,51,.5);box-shadow:0 0 0 3px rgba(255,51,51,.10)}
.search input{
  background:none;border:0;outline:0;color:var(--txt);font-size:12.5px;width:100%;
}
.search input::placeholder{color:var(--muted2)}
.iconbtn{
  width:32px;height:32px;border-radius:9px;display:grid;place-items:center;
  color:var(--muted);border:1px solid transparent;transition:.15s ease;position:relative;
}
.iconbtn:hover{background:#151518;color:#fff;border-color:var(--line2)}
.iconbtn .badge{
  position:absolute;top:5px;right:5px;width:6px;height:6px;border-radius:50%;
  background:var(--red);box-shadow:0 0 8px var(--red);
}
.btn{
  display:inline-flex;align-items:center;gap:7px;padding:7px 13px;border-radius:9px;
  font-size:12.5px;font-weight:550;border:1px solid var(--line2);background:#141417;
  color:var(--txt2);transition:.15s ease;white-space:nowrap;
}
.btn:hover{background:#1b1b1f;color:#fff;border-color:#3a3a41;transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn.red{background:linear-gradient(180deg,#ff3b3b,#e02525);border-color:#ff4d4d;color:#fff;box-shadow:0 8px 22px -12px rgba(255,51,51,.9)}
.btn.red:hover{filter:brightness(1.07)}
.btn.ghost{background:transparent}
.btn.sm{padding:5px 10px;font-size:11.5px;border-radius:8px}

/* ---------------------------------------------------------------- content */
.content{padding:20px;display:flex;flex-direction:column;gap:18px;max-width:1560px;width:100%;margin:0 auto}
.card{
  background:linear-gradient(180deg,var(--card),#101012);
  border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);
}
.card.pad{padding:16px 18px}
.card-h{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--line)}
.card-h .t{font-size:13.5px;font-weight:640;letter-spacing:.2px}
.card-h .s{font-size:11.5px;color:var(--muted)}
.card-h .right{margin-left:auto;display:flex;align-items:center;gap:8px}
.hicon{
  width:26px;height:26px;border-radius:8px;display:grid;place-items:center;
  background:#161619;border:1px solid var(--line2);color:var(--red);
}
.hicon.blue{color:var(--blue)}.hicon.green{color:var(--green)}.hicon.yellow{color:var(--yellow)}

/* ---------------------------------------------------------------- hero */
.hero{
  position:relative;overflow:hidden;border-radius:18px;border:1px solid var(--line);
  background:linear-gradient(120deg,#111113 0%,#131316 42%,#170c0d 100%);
  padding:26px 28px;display:flex;gap:26px;align-items:center;
}
.hero::after{
  content:'';position:absolute;right:-90px;top:-70px;width:420px;height:420px;border-radius:50%;
  background:radial-gradient(circle,rgba(255,51,51,.34),transparent 62%);filter:blur(6px);
  transition:opacity .5s ease;
}
.hero.legit::after{background:radial-gradient(circle,rgba(47,213,116,.26),transparent 62%)}
.hero.warn::after{background:radial-gradient(circle,rgba(255,176,32,.28),transparent 62%)}
.hero .grid-tex{
  position:absolute;inset:0;opacity:.35;pointer-events:none;
  background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);
  background-size:34px 34px;
  mask-image:linear-gradient(90deg,transparent,#000 30%);
}
.hero-l{position:relative;z-index:2;flex:1;min-width:0}
.eyebrow{
  display:inline-flex;align-items:center;gap:7px;font-size:10px;letter-spacing:.2em;
  color:var(--muted);text-transform:uppercase;margin-bottom:8px;
}
.hero h1{margin:0;font-size:clamp(30px,4vw,46px);font-weight:800;letter-spacing:.06em;line-height:1}
.hero h1 .glow{text-shadow:0 0 34px currentColor}
.hero .sub{color:var(--muted);font-size:12.5px;margin-top:9px;max-width:560px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
.chip{
  display:inline-flex;align-items:center;gap:7px;font-size:11px;padding:5px 10px;border-radius:999px;
  background:#151518;border:1px solid var(--line2);color:var(--txt2);font-family:var(--mono);
}
.chip .k{color:var(--muted2);letter-spacing:.06em}
.metaline{display:flex;flex-wrap:wrap;gap:22px;margin-top:18px}
.meta .lbl{font-size:9.5px;letter-spacing:.17em;color:var(--muted2);text-transform:uppercase}
.meta .val{font-family:var(--mono);font-size:15px;color:#fff;margin-top:3px;display:flex;align-items:center;gap:7px}
.copy{
  width:22px;height:22px;border-radius:6px;display:grid;place-items:center;color:var(--muted);
  border:1px solid var(--line2);background:#141417;transition:.14s;
}
.copy:hover{color:#fff;border-color:var(--red);background:#1c1214}

/* gauge */
.gauge{position:relative;z-index:2;width:172px;height:172px;flex:0 0 172px;display:grid;place-items:center}
.gauge svg{position:absolute;inset:0;transform:rotate(-90deg)}
.gauge .track{fill:none;stroke:#1d1d21;stroke-width:12}
.gauge .bar{fill:none;stroke-width:12;stroke-linecap:round;transition:stroke-dashoffset 1.15s cubic-bezier(.22,.7,.25,1)}
.gauge .core{position:relative;text-align:center}
.gauge .pct{font-size:34px;font-weight:800;letter-spacing:-.02em;line-height:1}
.gauge .cap{font-size:9.5px;letter-spacing:.17em;color:var(--muted2);text-transform:uppercase;margin-top:4px}
.gauge .risk{font-size:10.5px;color:var(--muted);margin-top:6px}

/* ---------------------------------------------------------------- actions */
.actions{display:flex;gap:10px;flex-wrap:wrap}

/* ---------------------------------------------------------------- grid */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
@media(max-width:1180px){.grid2{grid-template-columns:1fr}}
@media(max-width:900px){
  .sidebar{display:none}
  .grid3{grid-template-columns:1fr}
  .hero{flex-direction:column;align-items:flex-start}
}

/* stat cards */
.stat{
  border-radius:var(--r2);padding:14px 15px;border:1px solid var(--line2);
  background:#111113;position:relative;overflow:hidden;transition:.18s ease;
}
.stat:hover{transform:translateY(-3px);border-color:#3a3a41}
.stat::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:currentColor;opacity:.9}
.stat .n{font-size:30px;font-weight:800;color:currentColor;line-height:1.05}
.stat .l{font-size:9.5px;letter-spacing:.17em;color:var(--muted2);text-transform:uppercase;margin-top:6px;display:flex;align-items:center;gap:6px}
.stat .h{font-size:11px;color:var(--muted);margin-top:5px}
.stat.red{color:var(--red);background:linear-gradient(180deg,rgba(255,51,51,.07),#111113)}
.stat.yellow{color:var(--yellow);background:linear-gradient(180deg,rgba(255,176,32,.07),#111113)}
.stat.green{color:var(--green);background:linear-gradient(180deg,rgba(47,213,116,.07),#111113)}

/* pc info */
.kv{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:var(--r2);overflow:hidden}
.kv .cell{background:#111113;padding:11px 12px;min-width:0}
.kv .k{font-size:9.5px;letter-spacing:.15em;color:var(--muted2);text-transform:uppercase}
.kv .v{font-size:12.5px;color:var(--txt);margin-top:4px;word-break:break-word}
.kv .v.mono{font-family:var(--mono);font-size:12px}
.kv .v.good{color:var(--green)}.kv .v.bad{color:var(--red)}.kv .v.warn{color:var(--yellow)}
.rows{display:flex;flex-direction:column}
.rows .r{
  display:flex;align-items:center;gap:12px;padding:9.5px 4px;border-bottom:1px solid #1a1a1d;
  font-size:12.5px;transition:.13s;
}
.rows .r:last-child{border-bottom:0}
.rows .r:hover{background:#141417;padding-left:8px;padding-right:8px;border-radius:8px}
.rows .r .k{color:var(--muted);min-width:126px}
.rows .r .v{margin-left:auto;text-align:right;color:var(--txt);font-family:var(--mono);font-size:11.5px}
.rows .r .v.link{color:var(--blue)}

/* ---------------------------------------------------------------- results */
.results{display:grid;grid-template-columns:330px 1fr;gap:18px;align-items:start}
@media(max-width:1180px){.results{grid-template-columns:1fr}}
.res-head{padding:16px 18px 14px;border-bottom:1px solid var(--line)}
.res-head .top{display:flex;align-items:flex-start;gap:12px}
.res-head h2{margin:0;font-size:19px;font-weight:720;letter-spacing:-.2px}
.res-head .big{margin-left:auto;font-size:30px;font-weight:800;color:#fff;line-height:1}
.res-head .sub{font-size:11.5px;color:var(--muted);margin-top:5px}
.pill{
  display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:999px;
  border:1px solid var(--line2);background:#141417;font-size:11.5px;color:var(--txt2);transition:.14s;
}
.pill:hover{border-color:#3d3d44;color:#fff}
.pill.on{background:rgba(255,51,51,.14);border-color:rgba(255,51,51,.55);color:#fff}

.cats{padding:10px;display:flex;flex-direction:column;gap:7px;max-height:430px;overflow-y:auto}
.cat{
  display:flex;align-items:center;gap:11px;padding:11px 12px;border-radius:11px;
  background:#111113;border:1px solid var(--line);cursor:pointer;transition:.16s ease;text-align:left;width:100%;
}
.cat:hover{background:#161619;border-color:#33333a;transform:translateX(3px)}
.cat.on{
  background:linear-gradient(90deg,rgba(255,51,51,.16),rgba(255,51,51,.02));
  border-color:rgba(255,51,51,.5);box-shadow:0 0 24px -14px var(--red);
}
.cat .ci{width:28px;height:28px;flex:0 0 28px;border-radius:9px;display:grid;place-items:center;background:#1a1a1e;border:1px solid var(--line2);color:var(--muted)}
.cat.on .ci{color:var(--red);border-color:rgba(255,51,51,.4);background:rgba(255,51,51,.12)}
.cat .nm{font-size:12.5px;font-weight:600;color:var(--txt)}
.cat .st{font-size:10.5px;color:var(--muted2);font-family:var(--mono);margin-top:2px}
.cat .right{margin-left:auto;display:flex;align-items:center;gap:7px}
.tagmini{font-size:10px;font-family:var(--mono);padding:2px 7px;border-radius:6px;background:#191920;border:1px solid var(--line2);color:var(--muted)}
.tagmini.d{background:rgba(255,51,51,.14);border-color:rgba(255,51,51,.4);color:var(--red2)}
.tagmini.w{background:rgba(255,176,32,.12);border-color:rgba(255,176,32,.35);color:var(--yellow)}
.lock{color:var(--muted2)}

.filters{display:flex;gap:7px;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--line)}
.log{max-height:560px;overflow-y:auto;padding:8px 10px}
.item{
  display:flex;gap:12px;padding:11px 12px;border-radius:11px;border:1px solid transparent;
  transition:.15s ease;position:relative;
}
.item:hover{background:#141417;border-color:var(--line);transform:translateX(2px)}
.item + .item{margin-top:2px}
.item .ic{
  width:24px;height:24px;flex:0 0 24px;border-radius:50%;display:grid;place-items:center;margin-top:1px;
  background:#1b1b20;border:1px solid var(--line2);color:var(--muted);
}
.item.d .ic{background:rgba(255,51,51,.14);border-color:rgba(255,51,51,.5);color:var(--red2);box-shadow:0 0 16px -6px var(--red)}
.item.w .ic{background:rgba(255,176,32,.12);border-color:rgba(255,176,32,.42);color:var(--yellow)}
.item.l .ic{background:rgba(47,213,116,.12);border-color:rgba(47,213,116,.42);color:var(--green)}
.item .bd{min-width:0;flex:1}
.item .tt{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.item .ttl{font-size:12.8px;font-weight:600;color:#fff}
.item .dt{font-size:11.8px;color:var(--muted);margin-top:4px;word-break:break-word}
.item .tm{font-size:10.5px;color:var(--muted2);font-family:var(--mono);margin-top:5px}
.tag{
  font-size:9.5px;letter-spacing:.05em;padding:2px 7px;border-radius:5px;font-family:var(--mono);
  background:#1a1a1f;border:1px solid var(--line2);color:var(--muted);white-space:nowrap;
}
.tag.d{background:rgba(255,51,51,.13);border-color:rgba(255,51,51,.42);color:var(--red2)}
.tag.w{background:rgba(255,176,32,.12);border-color:rgba(255,176,32,.38);color:var(--yellow)}
.tag.l{background:rgba(47,213,116,.12);border-color:rgba(47,213,116,.38);color:var(--green)}
.tag.b{background:rgba(169,123,255,.12);border-color:rgba(169,123,255,.38);color:#c1a4ff}
.tag.i{background:rgba(91,157,255,.12);border-color:rgba(91,157,255,.38);color:#8fbcff}
.empty{padding:44px 18px;text-align:center;color:var(--muted2);font-size:12.5px}
.empty .big{font-size:34px;opacity:.35;margin-bottom:8px}

/* boot */
.pills{display:flex;gap:7px;flex-wrap:wrap}
.statpill{
  font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;padding:5px 10px;border-radius:999px;
  background:#141417;border:1px solid var(--line2);color:var(--muted);
}
.statpill b{color:#fff;font-weight:650}
.anom{border:1px solid rgba(255,51,51,.42);background:rgba(255,51,51,.06);border-radius:11px;padding:12px 14px;margin-bottom:14px}
.anom .h{display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:650;color:var(--red2);margin-bottom:7px}
.anom ul{margin:0;padding-left:17px}
.anom li{font-size:12px;color:var(--txt2);margin:4px 0;font-family:var(--mono)}
.bootentries{display:flex;flex-direction:column;gap:8px}
.be{display:flex;align-items:center;gap:11px;padding:10px 12px;background:#111113;border:1px solid var(--line);border-radius:10px;transition:.15s}
.be:hover{border-color:#33333a;background:#161619}
.be .nm{font-family:var(--mono);font-size:11.8px;color:var(--txt);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.be .sub{font-size:10.5px;color:var(--muted2);font-family:var(--mono);margin-top:2px}
.be .right{margin-left:auto;display:flex;gap:7px;align-items:center}

/* providers */
.prov{display:grid;grid-template-columns:repeat(auto-fill,minmax(238px,1fr));gap:9px;padding:14px 16px}
.pv{display:flex;align-items:center;gap:10px;padding:9px 11px;background:#111113;border:1px solid var(--line);border-radius:10px;transition:.15s}
.pv:hover{border-color:#33333a;transform:translateY(-2px)}
.pv .st{width:7px;height:7px;border-radius:50%;flex:0 0 7px}
.pv .st.ok{background:var(--green);box-shadow:0 0 9px var(--green)}
.pv .st.blocked{background:var(--yellow);box-shadow:0 0 9px var(--yellow)}
.pv .st.skipped,.pv .st.missing,.pv .st.unavailable,.pv .st.failed{background:var(--muted2)}
.pv .nm{font-size:12px;font-weight:600}
.pv .nt{font-size:10.5px;color:var(--muted2);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pv .mt{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}

/* timeline */
.tl{padding:6px 18px 18px}
.tl .ev{display:flex;gap:13px;padding:9px 0;position:relative}
.tl .ev::before{content:'';position:absolute;left:5px;top:22px;bottom:-6px;width:1px;background:#1f1f23}
.tl .ev:last-child::before{display:none}
.tl .dot{width:11px;height:11px;border-radius:50%;background:#26262c;border:2px solid var(--bg);margin-top:4px;flex:0 0 11px;z-index:1}
.tl .ev.boot .dot{background:var(--blue);box-shadow:0 0 10px var(--blue)}
.tl .ev.game .dot{background:var(--green);box-shadow:0 0 10px var(--green)}
.tl .ev.prefetch .dot,.tl .ev.bam .dot{background:var(--yellow);box-shadow:0 0 10px var(--yellow)}
.tl .ev.detection .dot{background:var(--red);box-shadow:0 0 10px var(--red)}
.tl .lb{font-size:12.3px;color:var(--txt2)}
.tl .tm{font-size:10.5px;color:var(--muted2);font-family:var(--mono);margin-top:2px}

/* jars */
.jarlist{display:flex;flex-direction:column;gap:7px;padding:14px 16px}
.jar{display:flex;align-items:center;gap:11px;padding:9px 11px;background:#111113;border:1px solid var(--line);border-radius:10px;transition:.15s}
.jar:hover{border-color:#33333a}
.jar .fn{font-size:12px;color:var(--txt);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.jar .pth{font-size:10.5px;color:var(--muted2);font-family:var(--mono);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.jar .right{margin-left:auto;display:flex;gap:7px;align-items:center;flex-shrink:0}

/* footer */
.foot{
  display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;
  padding:16px 18px;border-top:1px solid var(--line);color:var(--muted2);font-size:11.5px;
}
.foot .cred{display:flex;align-items:center;gap:8px}
.foot .cred b{color:var(--txt2);font-weight:600}

/* toast */
.toast{
  position:fixed;bottom:22px;left:50%;transform:translate(-50%,20px);opacity:0;
  background:#17171b;border:1px solid var(--line2);border-radius:10px;padding:9px 15px;
  font-size:12.5px;color:#fff;box-shadow:0 20px 40px -20px #000;transition:.26s cubic-bezier(.2,.8,.3,1);
  z-index:99;pointer-events:none;
}
.toast.on{opacity:1;transform:translate(-50%,0)}

/* search overlay */
.hit{outline:1px solid rgba(255,51,51,.5);background:rgba(255,51,51,.05)}
.hl{background:rgba(255,176,32,.28);border-radius:3px;padding:0 2px;color:#fff}
.fade-in{animation:fade .32s ease both}
@keyframes fade{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}
</style>
</head>
<body>
<div class="app">

  <!-- ============================================================ sidebar -->
  <aside class="sidebar">
    <div class="brand">
      <div class="mark">(<span>*</span>&gt;</div>
      <div>
        <div class="nm">Ocean</div>
        <div class="sub">anticheat.ac</div>
      </div>
    </div>

    <nav class="nav">
      <h4>SERVICES</h4>
      <ul>
        <li><a href="#" class="on"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h7V3H3zM14 21h7v-9h-7zM14 8h7V3h-7zM3 21h7v-5H3z"/></svg>Dashboard</a></li>
        <li>
          <a href="#"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>Scanner
            <svg class="ico" style="margin-left:auto;width:12px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M6 9l6 6 6-6"/></svg>
          </a>
          <ul class="sublist">
            <li><a href="#"><span class="dot"></span>Pins</a></li>
            <li><a href="#results">Detections</a></li>
            <li><a href="#">Custom GUI</a></li>
          </ul>
        </li>
        <li><a href="#"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>Database
          <svg class="ico" style="margin-left:auto;width:12px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M9 6l6 6-6 6"/></svg></a></li>
        <li><a href="#"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6z"/></svg>Anti-Cheat
          <svg class="ico" style="margin-left:auto;width:12px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M9 6l6 6-6 6"/></svg></a></li>
      </ul>

      <h4>COMMUNITY <svg class="chev" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M6 9l6 6 6-6"/></svg></h4>
      <ul>
        <li><a href="#">Public Configs</a></li>
        <li><a href="#">Public Strings</a></li>
        <li><a href="#">Public GUIs</a></li>
        <li><a href="#">Detections marketplace</a></li>
      </ul>

      <h4>SUPPORT <svg class="chev" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M6 9l6 6 6-6"/></svg></h4>
      <ul><li><a href="#">Support</a></li></ul>

      <h4>RESOURCES <svg class="chev" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M6 9l6 6 6-6"/></svg></h4>
      <ul><li><a href="#">Documentation</a></li><li><a href="#">Changelog</a></li></ul>
    </nav>

    <div class="side-foot">
      <div class="row"><span class="pulse"></span> Local session &middot; read-only</div>
      <div class="row" style="font-family:var(--mono);font-size:10.5px">v<span id="side-ver">-</span> &middot; <span id="side-elev">-</span></div>
    </div>
  </aside>

  <!-- =============================================================== main -->
  <div class="main">
    <header class="topbar">
      <div class="crumb">
        <span>Dashboard</span><span class="sep">/</span>
        <span>Results</span><span class="sep">/</span>
        <span>Pin</span><span class="sep">/</span>
        <span class="cur" id="crumb-pin">-</span>
      </div>

      <label class="search">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--muted2)"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
        <input id="q" type="text" placeholder="Search findings, jars, paths..." autocomplete="off" />
        <kbd>Ctrl+K</kbd>
      </label>

      <button class="iconbtn" title="Notifications"><span class="badge"></span>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8a6 6 0 10-12 0c0 7-3 8-3 8h18s-3-1-3-8"/><path d="M13.7 21a2 2 0 01-3.4 0"/></svg>
      </button>
      <button class="btn sm" id="feedback">Feedback</button>
    </header>

    <div class="content">

      <!-- ---------------------------------------------------------- hero -->
      <section class="hero" id="hero">
        <div class="grid-tex"></div>
        <div class="hero-l">
          <div class="eyebrow">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 4v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6z"/></svg>
            Scan Results
          </div>
          <h1 id="verdict-word" class="glow">-</h1>
          <div class="sub">Detailed forensic breakdown and logic analysis of the requested execution context.</div>

          <div class="chips">
            <span class="chip"><span class="k">GAME</span> <span id="chip-game">-</span></span>
            <span class="chip"><span class="k">RISK HISTORY</span> <span id="chip-risk">-</span></span>
            <span class="chip"><span class="k">AI</span> not supported</span>
          </div>

          <div class="metaline">
            <div class="meta">
              <div class="lbl">Identity PIN</div>
              <div class="val"><span id="pin">-</span>
                <button class="copy" id="copy-pin" title="Copy PIN">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 012-2h10"/></svg>
                </button>
              </div>
            </div>
            <div class="meta">
              <div class="lbl">Scan duration</div>
              <div class="val" id="duration">-</div>
            </div>
            <div class="meta">
              <div class="lbl">Evidence sources</div>
              <div class="val" id="sources">-</div>
            </div>
            <div class="meta">
              <div class="lbl">Scanned</div>
              <div class="val" id="finished">-</div>
            </div>
          </div>
        </div>

        <div class="gauge">
          <svg viewBox="0 0 172 172">
            <circle class="track" cx="86" cy="86" r="66"></circle>
            <circle class="bar" id="gauge-bar" cx="86" cy="86" r="66"
                    stroke="#ff3333" stroke-dasharray="414.7" stroke-dashoffset="414.7"></circle>
          </svg>
          <div class="core">
            <div class="pct" id="gauge-pct">0%</div>
            <div class="cap">player risk</div>
            <div class="risk" id="gauge-risk">-</div>
          </div>
        </div>
      </section>

      <div class="actions">
        <button class="btn" id="btn-export">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M4 21h16"/></svg>
          Export
        </button>
        <button class="btn" id="btn-report">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 21V4h10l1 2h5v9h-6l-1-2H5"/></svg>
          Report Scan
        </button>
        <button class="btn ghost" id="btn-empty">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3l18 18"/><path d="M10.6 10.6a2 2 0 002.8 2.8"/><path d="M9.4 5.2A9.7 9.7 0 0112 5c5 0 9 4.5 9 7a11 11 0 01-2.4 3.6M6.2 6.6C4 8 3 10.7 3 12c0 2.5 4 7 9 7 1.3 0 2.5-.3 3.6-.8"/></svg>
          <span id="empty-label">Hide empty tabs</span>
        </button>
      </div>

      <!-- ------------------------------------------------ overview grid -->
      <section class="grid2">
        <div class="card">
          <div class="card-h">
            <div class="hicon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg></div>
            <div>
              <div class="t">Scan overview</div>
              <div class="s">Weighted evidence, not raw counts</div>
            </div>
            <div class="right"><span class="tag d" id="ov-pill">-</span></div>
          </div>
          <div style="padding:16px 18px">
            <div class="grid3">
              <div class="stat red">
                <div class="n" id="c-det">0</div>
                <div class="l">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 3l8 3v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6z"/></svg>
                  Detections
                </div>
                <div class="h" id="c-det-h">-</div>
              </div>
              <div class="stat yellow">
                <div class="n" id="c-warn">0</div>
                <div class="l">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 3l9.5 17H2.5z"/><path d="M12 10v4M12 17.5v.01"/></svg>
                  Warnings
                </div>
                <div class="h" id="c-warn-h">-</div>
              </div>
              <div class="stat green">
                <div class="n" id="c-legit">0</div>
                <div class="l">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M20 6L9 17l-5-5"/></svg>
                  Legit
                </div>
                <div class="h" id="c-legit-h">-</div>
              </div>
            </div>
            <div class="rows" style="margin-top:14px">
              <div class="r"><span class="k">Confidence pass</span><span class="v" id="ov-down">-</span></div>
              <div class="r"><span class="k">Hash verified</span><span class="v" id="ov-verified">-</span></div>
              <div class="r"><span class="k">Elevated</span><span class="v" id="ov-elev">-</span></div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-h">
            <div class="hicon blue"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg></div>
            <div>
              <div class="t">PC Information</div>
              <div class="s">Information about the user's PC</div>
            </div>
            <div class="right"><a class="btn sm" href="#activity">View Stats &rarr;</a></div>
          </div>
          <div style="padding:16px 18px">
            <div class="kv">
              <div class="cell"><div class="k">Boot time</div><div class="v" id="pi-boot">-</div></div>
              <div class="cell"><div class="k">VPN</div><div class="v" id="pi-vpn">-</div></div>
              <div class="cell"><div class="k">Recycle</div><div class="v" id="pi-recycle">-</div></div>
              <div class="cell"><div class="k">System</div><div class="v" id="pi-os">-</div></div>
              <div class="cell"><div class="k">Install date</div><div class="v mono" id="pi-install">-</div></div>
              <div class="cell"><div class="k">Country</div><div class="v" id="pi-country">-</div></div>
            </div>
            <div class="rows" style="margin-top:12px">
              <div class="r"><span class="k">Game</span><span class="v" id="pi-game">-</span></div>
              <div class="r"><span class="k">Window text</span><span class="v" id="pi-window">-</span></div>
              <div class="r"><span class="k">CPU / GPU</span><span class="v" id="pi-cpu">-</span></div>
              <div class="r"><span class="k">Memory</span><span class="v" id="pi-ram">-</span></div>
              <div class="r"><span class="k">Host / user</span><span class="v" id="pi-host">-</span></div>
            </div>
          </div>
        </div>
      </section>

      <!-- ------------------------------------------------------ results -->
      <section class="results" id="results">
        <div class="card">
          <div class="res-head">
            <div class="top">
              <div>
                <h2>Detection Results</h2>
                <div class="sub" id="res-sub">-</div>
              </div>
              <div class="big" id="res-total">0</div>
            </div>
          </div>
          <div class="cats" id="cats"></div>
        </div>

        <div style="display:flex;flex-direction:column;gap:18px;min-width:0">
          <div class="card">
            <div class="card-h">
              <div class="hicon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/></svg></div>
              <div class="t" id="list-title">Overview</div>
              <div class="right">
                <button class="btn sm" id="btn-copy">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 012-2h10"/></svg>
                  Copy
                </button>
              </div>
            </div>
            <div class="filters" id="filters"></div>
            <div class="log" id="log"></div>
          </div>

          <div class="card" id="bootcard">
            <div class="card-h">
              <div class="hicon yellow"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6z"/></svg></div>
              <div>
                <div class="t" id="boot-title">Boot sequence</div>
                <div class="s">Recorded boot sequence detail for this machine.</div>
              </div>
              <div class="right pills" id="boot-pills"></div>
            </div>
            <div style="padding:16px 18px">
              <div id="boot-anom"></div>
              <div class="kv" id="boot-meta" style="margin-bottom:14px"></div>
              <div class="bootentries" id="boot-entries"></div>
            </div>
          </div>

          <div class="card">
            <div class="card-h">
              <div class="hicon green"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h10"/></svg></div>
              <div>
                <div class="t">Collection providers</div>
                <div class="s">What was read, what was blocked, and why</div>
              </div>
            </div>
            <div class="prov" id="providers"></div>
          </div>

          <div class="card">
            <div class="card-h">
              <div class="hicon blue"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/></svg></div>
              <div>
                <div class="t">Jar inventory</div>
                <div class="s" id="jar-sub">Indexed archives with hash verification status</div>
              </div>
            </div>
            <div class="jarlist" id="jars"></div>
          </div>
        </div>
      </section>

      <!-- ---------------------------------------------------- timeline -->
      <section class="card" id="activity">
        <div class="card-h">
          <div class="hicon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8v4l3 2"/><circle cx="12" cy="12" r="9"/></svg></div>
          <div>
            <div class="t">PC Activity</div>
            <div class="s">Live forensic timeline since this boot</div>
          </div>
        </div>
        <div class="tl" id="timeline"></div>
      </section>

      <footer class="foot">
        <div class="cred">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--red)"><path d="M12 2l8 4v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6z"/></svg>
          Detection Logic Inspired by <b>x1r scanner</b> &amp; <b>Ocean Anti-Cheat</b>
        </div>
        <div style="font-family:var(--mono);font-size:10.5px">
          <span id="foot-pin">-</span> &middot; v<span id="foot-ver">-</span> &middot; read-only collection
        </div>
      </footer>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
(function () {
  'use strict';

  var DATA = __OCEAN_DATA__ || {};

  /* ------------------------------------------------------------ helpers */
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function attr(s) { return esc(s).replace(/`/g, '&#96;'); }
  function el(tag, cls, html) {
    var d = document.createElement(tag);
    if (cls) d.className = cls;
    if (html != null) d.innerHTML = html;
    return d;
  }
  function safeArray(v) { return Object.prototype.toString.call(v) === '[object Array]' ? v : []; }
  function num(v, d) { var n = parseInt(v, 10); return isNaN(n) ? (d || 0) : n; }

  function icon(name) {
    var p = {
      overview: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>',
      bug: '<path d="M8 6h8v6a4 4 0 01-8 0z"/><path d="M12 3v3M4 12h4M16 12h4M5 7l3 3M19 7l-3 3M5 19l3-3M19 19l-3-3"/>',
      file: '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5"/>',
      target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.4"/>',
      java: '<path d="M12 3c3 3-2 4 0 7"/><path d="M9 13c-2 1-2 4 1 5h4c3-1 3-4 1-5"/><path d="M8 19c2 1.5 6 1.5 8 0"/>',
      boot: '<path d="M12 3l8 3v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6z"/>',
      ghost: '<path d="M5 21V10a7 7 0 0114 0v11l-3-2-2 2-2-2-2 2z"/><path d="M9 10v.01M15 10v.01"/>',
      cam: '<rect x="3" y="6" width="13" height="12" rx="2"/><path d="M16 10l5-3v10l-5-3"/>',
      ps: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
      ai: '<path d="M12 3l1.8 4.7L18.5 9.5 13.8 11.3 12 16l-1.8-4.7L5.5 9.5l4.7-1.8z"/>',
      shield: '<path d="M12 3l8 3v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6z"/>',
      grid: '<path d="M3 12h7V3H3zM14 21h7v-9h-7zM14 8h7V3h-7zM3 21h7v-5H3z"/>'
    }[name] || '<circle cx="12" cy="12" r="8"/>';
    return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">' + p + '</svg>';
  }

  function ago(iso) {
    var t = Date.parse(iso);
    if (!t) return '';
    var s = Math.round((Date.now() - t) / 1000);
    if (s < 0) s = 0;
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.round(s / 60) + 'm ago';
    if (s < 86400) return Math.round(s / 3600) + 'h ago';
    return Math.round(s / 86400) + 'd ago';
  }
  function when(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }
  function toast(msg) {
    var n = $('toast');
    n.textContent = msg;
    n.className = 'toast on';
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { n.className = 'toast'; }, 2400);
  }
  function copyText(text) {
    var done = function () { toast('Copied to clipboard'); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(text, done); });
    } else { fallback(text, done); }
  }
  function fallback(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed'); }
    document.body.removeChild(ta);
  }
  function highlight(text, q) {
    var safe = esc(text);
    if (!q) return safe;
    var rx = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig');
    return safe.replace(rx, '<span class="hl">$1</span>');
  }

  /* -------------------------------------------------------------- state */
  var V = DATA.verdict || {};
  var SYS = DATA.system || {};
  var META = DATA.meta || {};
  var BOOT = DATA.boot || {};
  var F = safeArray(DATA.findings);
  var ACT = safeArray(DATA.activity);
  var PROV = safeArray(DATA.providers);
  var JARS = safeArray(DATA.jars);

  var CATEGORY_ORDER = [
    'Overview', 'Suspicious logs', 'Cheater Records', 'Bypass Methods',
    'Files Activity', 'Minecraft Mods', 'Java Connections', 'Boot Sequence',
    'Recording Software', 'PowerShell History', 'Accounts'
  ];
  var FILTERS = [
    ['all', 'All'], ['Detection', 'Detection'], ['Warning', 'Warning'],
    ['Legit', 'Legit'], ['In Instance', 'In instance'], ['Boot', 'Boot']
  ];

  var state = { cat: null, filter: 'all', showEmpty: false, q: '' };
  var CAT_ICON = {
    'Overview': 'overview', 'Suspicious logs': 'bug', 'Cheater Records': 'target',
    'Bypass Methods': 'ghost', 'Files Activity': 'file', 'Minecraft Mods': 'java',
    'Java Connections': 'java', 'Boot Sequence': 'boot', 'Recording Software': 'cam',
    'PowerShell History': 'ps', 'AI Opinion': 'ai', 'Accounts': 'target'
  };

  /* --------------------------------------------------------------- hero */
  function paintHero() {
    var label = String(V.label || 'LEGIT');
    var score = num(V.score, 0);
    var hero = $('hero');
    var word = $('verdict-word');
    var color = '#ff3333';

    if (label === 'LEGIT') { color = '#2fd574'; hero.classList.add('legit'); }
    else if (label === 'SUSPICIOUS') { color = '#ffb020'; hero.classList.add('warn'); }
    else { color = '#ff3333'; }

    word.textContent = label;
    word.style.color = color;

    var C = 414.7;
    var bar = $('gauge-bar');
    bar.setAttribute('stroke', color);
    bar.style.strokeDashoffset = String(C - (C * Math.min(100, Math.max(0, score)) / 100));
    $('gauge-pct').textContent = score + '%';
    $('gauge-pct').style.color = color;
    $('gauge-risk').textContent = label === 'LEGIT' ? 'low risk' : (label === 'CHEATING' ? 'high risk' : 'elevated risk');

    $('pin').textContent = META.pin || '-';
    $('crumb-pin').textContent = META.pin || '-';
    $('foot-pin').textContent = 'pin ' + (META.pin || '-');
    $('duration').textContent = num(META.durationSeconds, 0) + 's';
    $('finished').textContent = when(META.finishedAt) || '-';
    $('sources').textContent = num(V.sources, 0);
    $('chip-game').textContent = String(SYS.game || 'Minecraft Java').toUpperCase();
    $('chip-risk').textContent = num(V.detections, 0) + ' det / ' + num(V.warnings, 0) + ' warn';

    $('side-ver').textContent = META.version || '-';
    $('foot-ver').textContent = META.version || '-';
    $('side-elev').textContent = META.elevated ? 'elevated' : 'unelevated';
  }

  /* -------------------------------------------------------- stat cards */
  function paintStats() {
    var det = num(V.detections, 0), warn = num(V.warnings, 0), leg = num(V.legit, 0);
    $('c-det').textContent = det;
    $('c-warn').textContent = warn;
    $('c-legit').textContent = leg;
    $('ov-pill').textContent = det > 0 ? 'Detections' : (warn > 0 ? 'Warnings' : 'Clean');
    $('ov-pill').className = 'tag ' + (det > 0 ? 'd' : (warn > 0 ? 'w' : 'l'));
    $('c-det-h').textContent = num(V.confirmed, 0) + ' confirmed';
    $('c-warn-h').textContent = det + warn + leg + ' total findings';
    $('c-legit-h').textContent = 'negative checks passed';
    $('ov-down').textContent = num(V.downgraded, 0) === 0
      ? 'no rows demoted'
      : num(V.downgraded, 0) + ' heuristic row(s) demoted to warning';
    $('ov-verified').textContent = num(META.verified, 0) + ' jar(s) whitelisted';
    $('ov-elev').textContent = META.elevated ? 'yes' : 'no - some sources skipped';
    $('ov-elev').className = 'v ' + (META.elevated ? 'good' : 'warn');
  }

  /* ---------------------------------------------------------- pc info */
  function paintPc() {
    $('pi-boot').textContent = ago(SYS.bootTime) || '-';
    $('pi-vpn').textContent = SYS.vpn || 'No';
    $('pi-vpn').className = 'v ' + (SYS.vpn === 'Yes' ? 'bad' : 'good');
    $('pi-recycle').textContent = SYS.recycleLatest ? ago(SYS.recycleLatest) : 'none';
    $('pi-os').textContent = (SYS.os || '-') + (SYS.build ? ' (' + SYS.build + ')' : '');
    $('pi-install').textContent = SYS.installDate || '-';
    $('pi-country').textContent = SYS.country || 'Unknown';
    $('pi-game').textContent = (SYS.gameRunning ? 'running - ' : 'not running - ') + (SYS.gameStart ? ago(SYS.gameStart) : 'no start time');
    $('pi-game').className = 'v ' + (SYS.gameRunning ? 'good' : 'warn');
    $('pi-window').textContent = SYS.windowText || 'no window title captured';
    $('pi-cpu').textContent = [SYS.cpu, SYS.gpu].filter(Boolean).join(' / ') || '-';
    $('pi-ram').textContent = SYS.ram || '-';
    $('pi-host').textContent = [SYS.hostname, SYS.user].filter(Boolean).join(' / ') || '-';

    if (SYS.vpnDetail) $('pi-vpn').title = SYS.vpnDetail;
  }

  /* ------------------------------------------------------- categories */
  function counts() {
    var map = {};
    F.forEach(function (f) { map[f.category] = (map[f.category] || 0) + 1; });
    return map;
  }
  function sevOf(list) {
    var d = 0, w = 0;
    list.forEach(function (f) {
      if (f.severity === 'Detection') d++;
      else if (f.severity === 'Warning') w++;
    });
    return { d: d, w: w };
  }
  function renderCats() {
    var map = counts();
    var names = [];
    CATEGORY_ORDER.forEach(function (n) { if (map[n]) names.push(n); });
    Object.keys(map).forEach(function (n) { if (names.indexOf(n) === -1) names.push(n); });
    if (state.showEmpty) {
      CATEGORY_ORDER.forEach(function (n) { if (names.indexOf(n) === -1) names.push(n); });
    }
    if (!state.cat || names.indexOf(state.cat) === -1) state.cat = names[0] || null;

    var total = F.length;
    var box = $('cats');
    box.innerHTML = '';
    names.forEach(function (name) {
      var list = F.filter(function (f) { return f.category === name; });
      var s = sevOf(list);
      var pct = total ? Math.round(list.length / total * 100) : 0;
      var b = el('button', 'cat' + (state.cat === name ? ' on' : ''));
      var stats = list.length
        ? list.length + ' (' + pct + '%)'
        : 'empty';
      var right = '';
      if (s.d) right += '<span class="tagmini d">' + s.d + '</span>';
      if (s.w) right += '<span class="tagmini w">' + s.w + '</span>';
      right += '<span class="tagmini">' + esc(stats) + '</span>';
      if (name === 'AI Opinion') right = '<span class="tagmini">AI</span>';
      b.innerHTML =
        '<span class="ci">' + icon(CAT_ICON[name] || 'grid') + '</span>' +
        '<span><span class="nm">' + esc(name) + '</span>' +
        '<span class="st">' + esc(stats) + '</span></span>' +
        '<span class="right">' + right + '</span>';
      b.onclick = function () { state.cat = name; renderCats(); renderList(); };
      box.appendChild(b);
    });

    $('res-total').textContent = total;
    $('res-sub').textContent = total + ' total logs found across ' + names.length + ' categories';
  }

  /* ---------------------------------------------------------- filters */
  function matchesFilter(f) {
    if (state.filter === 'all') return true;
    if (state.filter === 'Detection' || state.filter === 'Warning' || state.filter === 'Legit') {
      return f.severity === state.filter;
    }
    return safeArray(f.tags).some(function (t) { return String(t) === state.filter; });
  }
  function matchesQuery(f) {
    if (!state.q) return true;
    var q = state.q.toLowerCase();
    return (String(f.title) + ' ' + String(f.detail) + ' ' + String(f.category) + ' ' +
      safeArray(f.tags).join(' ')).toLowerCase().indexOf(q) !== -1;
  }
  function renderFilters() {
    var box = $('filters');
    box.innerHTML = '';
    FILTERS.forEach(function (f) {
      var b = el('button', 'pill' + (state.filter === f[0] ? ' on' : ''), esc(f[1]));
      b.onclick = function () { state.filter = f[0]; renderFilters(); renderList(); };
      box.appendChild(b);
    });
  }

  /* -------------------------------------------------------- log rows */
  function tagHtml(tag) {
    var t = String(tag);
    var cls = 'tag';
    if (t === 'Detection') cls += ' d';
    else if (t === 'Warning') cls += ' w';
    else if (t === 'Legit') cls += ' l';
    else if (t === 'Boot') cls += ' b';
    else if (t === 'In Instance') cls += ' i';
    return '<span class="' + cls + '">' + esc(t) + '</span>';
  }
  function sevClass(f) {
    if (f.severity === 'Detection') return 'd';
    if (f.severity === 'Warning') return 'w';
    if (f.severity === 'Legit') return 'l';
    return 'i';
  }
  function sevGlyph(f) {
    if (f.severity === 'Detection') return '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M12 7v6M12 17v.01"/><circle cx="12" cy="12" r="9"/></svg>';
    if (f.severity === 'Warning') return '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17.5v.01"/></svg>';
    if (f.severity === 'Legit') return '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6"><path d="M20 6L9 17l-5-5"/></svg>';
    return '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="12" cy="12" r="9"/><path d="M12 8v.01M12 11v5"/></svg>';
  }

  function activeRows() {
    if (state.q) return F.filter(matchesQuery).filter(matchesFilter);
    return F.filter(function (f) { return f.category === state.cat; }).filter(matchesFilter);
  }

  function renderList() {
    var rows = activeRows();
    var box = $('log');
    $('list-title').textContent = state.q
      ? 'Search results for "' + state.q + '"'
      : (state.cat || 'Results');

    if (!rows.length) {
      box.innerHTML = '<div class="empty"><div class="big">&#9678;</div>' +
        (state.q ? 'No findings match your search.' : 'No findings in this category with the current filter.') +
        '</div>';
      return;
    }

    box.innerHTML = rows.map(function (f) {
      var tags = safeArray(f.tags).map(tagHtml).join('');
      var meta = [];
      if (f.time) meta.push(when(f.time));
      if (f.confirmed) meta.push('confirmed evidence');
      return '<div class="item ' + sevClass(f) + ' fade-in">' +
        '<span class="ic">' + sevGlyph(f) + '</span>' +
        '<div class="bd">' +
          '<div class="tt"><span class="ttl">' + highlight(f.title, state.q) + '</span>' + tags + '</div>' +
          (f.detail ? '<div class="dt">' + highlight(f.detail, state.q) + '</div>' : '') +
          (meta.length ? '<div class="tm">' + esc(meta.join('  &middot;  ')) + '</div>' : '') +
        '</div>' +
      '</div>';
    }).join('');
  }

  /* ------------------------------------------------------------- boot */
  function paintBoot() {
    var anoms = safeArray(BOOT.anomalies);
    var entries = safeArray(BOOT.entries);
    $('boot-title').textContent = 'Boot sequence (' + entries.length + ')';

    var pills = [
      ['anomalies', anoms.length],
      ['secure boot', BOOT.secureBoot === true ? 'on' : (BOOT.secureBoot === false ? 'off' : 'n/a')],
      ['fast startup', BOOT.fastStartup === true ? 'on' : (BOOT.fastStartup === false ? 'off' : 'n/a')]
    ];
    $('boot-pills').innerHTML = pills.map(function (p) {
      return '<span class="statpill">' + esc(p[0]) + ': <b>' + esc(String(p[1])) + '</b></span>';
    }).join('');

    $('boot-anom').innerHTML = anoms.length
      ? '<div class="anom"><div class="h">' +
          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3"><path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17.5v.01"/></svg>' +
          'Anomalies (' + anoms.length + ')</div><ul>' +
          anoms.map(function (a) { return '<li>' + esc(a) + '</li>'; }).join('') +
        '</ul></div>'
      : '<div class="anom" style="border-color:rgba(47,213,116,.35);background:rgba(47,213,116,.05)">' +
          '<div class="h" style="color:#2fd574">Anomalies (0)</div>' +
          '<div style="font-size:12px;color:var(--muted)">No boot-chain anomalies were recorded.</div></div>';

    var meta = [
      ['BIOS vendor', BOOT.biosVendor], ['BIOS version', BOOT.biosVersion],
      ['Board product', BOOT.boardProduct], ['Board maker', BOOT.boardManufacturer],
      ['BIOS date', BOOT.biosDate], ['Uptime', BOOT.uptimeMinutes + ' min']
    ].filter(function (r) { return r[1] !== '' && r[1] != null; });

    $('boot-meta').innerHTML = meta.map(function (r) {
      return '<div class="cell"><div class="k">' + esc(r[0]) + '</div><div class="v mono">' + esc(r[1]) + '</div></div>';
    }).join('');

    $('boot-entries').innerHTML = entries.length ? entries.map(function (e) {
      return '<div class="be">' +
        '<span class="hicon" style="width:24px;height:24px;color:var(--muted)">' +
          '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/></svg>' +
        '</span>' +
        '<span style="min-width:0"><span class="nm">#' + (1) + ' ' + esc(e.name) + '</span>' +
        '<span class="sub">' + esc(e.detail || '') + '</span></span>' +
        '<span class="right"><span class="tag">' + esc(e.kind || '') + '</span></span>' +
      '</div>';
    }).join('') : '<div class="empty" style="padding:18px">No boot entries recorded.</div>';
  }

  /* -------------------------------------------------------- providers */
  function paintProviders() {
    var box = $('providers');
    if (!PROV.length) { box.innerHTML = '<div class="empty">No provider data.</div>'; return; }
    box.innerHTML = PROV.map(function (p) {
      var st = String(p.status || '').toLowerCase();
      return '<div class="pv" title="' + attr(p.note || '') + '">' +
        '<span class="st ' + attr(st) + '"></span>' +
        '<span style="min-width:0"><span class="nm">' + esc(p.name) + '</span>' +
        '<span class="nt">' + esc(p.note || st) + '</span></span>' +
        '<span class="mt">' + esc(String(p.matched == null ? '-' : p.matched)) + '</span>' +
      '</div>';
    }).join('');
  }

  /* ------------------------------------------------------------- jars */
  function paintJars() {
    var box = $('jars');
    var verified = JARS.filter(function (j) { return j.verified; }).length;
    $('jar-sub').textContent = JARS.length + ' archives indexed - ' + verified + ' hash-verified';
    if (!JARS.length) { box.innerHTML = '<div class="empty">No jars were located.</div>'; return; }
    box.innerHTML = JARS.map(function (j) {
      var kb = Math.round(num(j.size, 0) / 1024);
      var status = j.error
        ? '<span class="tag w">unreadable</span>'
        : (j.verified ? '<span class="tag l">verified</span>' : '<span class="tag">unverified</span>');
      return '<div class="jar">' +
        '<span class="hicon" style="width:24px;height:24px;color:var(--muted)">' +
          '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/></svg>' +
        '</span>' +
        '<span style="min-width:0"><span class="fn">' + esc(j.name) + '</span>' +
        '<span class="pth">' + esc(j.path) + '</span></span>' +
        '<span class="right">' +
          '<span class="tag">' + (j.entries || 0) + ' entries</span>' +
          '<span class="tag">' + kb + ' KB</span>' +
          status +
        '</span>' +
      '</div>';
    }).join('');
  }

  /* --------------------------------------------------------- timeline */
  function paintTimeline() {
    var box = $('timeline');
    var events = ACT.slice().sort(function (a, b) {
      return (Date.parse(b.time) || 0) - (Date.parse(a.time) || 0);
    });
    if (!events.length) { box.innerHTML = '<div class="empty">No timeline events were recorded.</div>'; return; }
    box.innerHTML = events.map(function (e) {
      var kind = String(e.kind || 'info');
      return '<div class="ev ' + attr(kind) + '">' +
        '<span class="dot"></span>' +
        '<span><span class="lb">' + esc(e.label) + '</span>' +
        '<span class="tm">' + esc(when(e.time) || 'no timestamp') + '</span></span>' +
      '</div>';
    }).join('');
  }

  /* ----------------------------------------------------------- export */
  function reportText() {
    var lines = [];
    lines.push('Ocean SS - ' + (META.pin || '') + ' - ' + (V.label || '') + ' (' + (V.score || 0) + '%)');
    lines.push('host ' + (SYS.hostname || '-') + ' / user ' + (SYS.user || '-'));
    lines.push('detections ' + (V.detections || 0) + '  warnings ' + (V.warnings || 0) + '  legit ' + (V.legit || 0));
    lines.push('');
    F.forEach(function (f) {
      lines.push('[' + f.severity + '] ' + f.category + ' :: ' + f.title);
      if (f.detail) lines.push('        ' + f.detail);
    });
    return lines.join('\n');
  }

  /* ------------------------------------------------------------ events */
  function bind() {
    $('copy-pin').onclick = function () { copyText(META.pin || ''); };
    $('btn-copy').onclick = function () { copyText(reportText()); };

    $('btn-export').onclick = function () {
      try {
        var blob = new Blob([JSON.stringify(DATA, null, 2)], { type: 'application/json' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'ocean-scan-' + (META.pin || 'report') + '.json';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
        toast('Report exported');
      } catch (e) { toast('Export failed'); }
    };

    $('btn-report').onclick = function () {
      var text = reportText();
      copyText(text);
      toast('Report copied - paste it into your ticket');
    };

    $('btn-empty').onclick = function () {
      state.showEmpty = !state.showEmpty;
      $('empty-label').textContent = state.showEmpty ? 'Hide empty tabs' : 'Show empty tabs';
      renderCats(); renderList();
    };

    $('feedback').onclick = function () { toast('Feedback: report an issue with pin ' + (META.pin || '-')); };

    var q = $('q');
    q.addEventListener('input', function () {
      state.q = q.value.trim();
      renderList();
    });
    document.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault(); q.focus(); q.select();
      }
      if (e.key === 'Escape' && document.activeElement === q) {
        q.value = ''; state.q = ''; renderList(); q.blur();
      }
    });
  }

  /* -------------------------------------------------------------- init */
  function init() {
    paintHero();
    paintStats();
    paintPc();
    renderFilters();
    renderCats();
    renderList();
    paintBoot();
    paintProviders();
    paintJars();
    paintTimeline();
    bind();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
</script>
</body>
</html>
'@

# ---------------------------------------------------------------------------
# 11. Local dashboard server
# ---------------------------------------------------------------------------

function Send-HttpResponse {
    param(
        [Parameter(Mandatory)]$Context,
        [int]$StatusCode,
        [string]$ContentType,
        [byte[]]$Body
    )

    $res = $Context.Response
    try {
        $res.StatusCode = $StatusCode
        if ($ContentType) { $res.ContentType = $ContentType }
        $res.Headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        $res.Headers['X-Content-Type-Options'] = 'nosniff'
        if ($null -ne $Body -and $Body.Length -gt 0) {
            $res.ContentLength64 = $Body.Length
            $res.OutputStream.Write($Body, 0, $Body.Length)
        }
        else {
            $res.ContentLength64 = 0
        }
    }
    catch {
        Write-Verbose "Response failed: $($_.Exception.Message)"
    }
    finally {
        try { $res.OutputStream.Close() } catch { }
        try { $res.Close() } catch { }
    }
}function Start-WebServer {
    param(
        [int]$Port = 8080,
        [Parameter(Mandatory)][string]$Html,
        [Parameter(Mandatory)][string]$Json,
        [switch]$OpenBrowser,
        [switch]$KeepAlive,
        [int]$AutoShutdownSeconds = 25
    )

    $prefix = "http://localhost:$Port/"
    $listener = New-Object System.Net.HttpListener

    # Binding happens entirely inside the guarded block so a failed prefix or a
    # port already in use still falls through to Close() - an unclosed listener
    # is what leaves port 8080 locked for the next run.
    try {
        $listener.Prefixes.Add($prefix)
        $listener.Start()
    }
    catch {
        Write-Host ''
        Write-Host "  [x] Could not bind $prefix" -ForegroundColor Red
        Write-Host "      $($_.Exception.Message)" -ForegroundColor DarkGray
        Write-Host '      Port 8080 may be in use, or the URL ACL is missing.' -ForegroundColor DarkGray
        Write-Host '      Fix: run an elevated PowerShell once and execute' -ForegroundColor DarkGray
        Write-Host "           netsh http add urlacl url=http://localhost:$Port/ user=$env:USERNAME" -ForegroundColor DarkGray
        try { $listener.Close() } catch { }
        return
    }

    $htmlBytes = [Text.Encoding]::UTF8.GetBytes($Html)
    $jsonBytes = [Text.Encoding]::UTF8.GetBytes($Json)
    $favicon   = [byte[]]@()
    $canReadKey = $true
    $script:StopRequested = $false
    $deadline = (Get-Date).AddSeconds($AutoShutdownSeconds)
    $autoStopped = $false

    if ($OpenBrowser) {
        try { Start-Process "http://localhost:$Port/" | Out-Null } catch { }
    }

    Write-Host ''
    Write-Host "  Dashboard live:  http://localhost:$Port/" -ForegroundColor Cyan
    if ($KeepAlive) {
        Write-Host '  Press any key to stop the server...' -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Auto-shutdown in $AutoShutdownSeconds s  (rerun with -KeepAlive to hold it open)" -ForegroundColor DarkGray
    }
    Write-Host ''

    try {
        while ($listener.IsListening -and -not $script:StopRequested) {
            $async = $null
            try { $async = $listener.BeginGetContext($null, $null) }
            catch { break }

            while (-not $async.AsyncWaitHandle.WaitOne(120)) {
                if (-not $listener.IsListening) { break }

                # Hard deadline: the port is released 25 s after the scan by
                # default so a forgotten window never keeps the machine bound.
                if (-not $KeepAlive -and -not $script:StopRequested -and (Get-Date) -ge $deadline) {
                    $script:StopRequested = $true
                    $autoStopped = $true
                    break
                }

                if ($KeepAlive -and $canReadKey) {
                    try {
                        if ([Console]::IsInputRedirected) { $canReadKey = $false }
                        elseif ([Console]::KeyAvailable) {
                            $null = [Console]::ReadKey($true)
                            $script:StopRequested = $true
                            break
                        }
                    }
                    catch { $canReadKey = $false }
                }
            }

            if ($script:StopRequested) { break }
            if (-not $listener.IsListening) { break }

            $context = $null
            try { $context = $listener.EndGetContext($async) }
            catch { break }
            if ($null -eq $context) { break }

            $path = '/'
            try { $path = [string]$context.Request.Url.AbsolutePath } catch { }

            try {
                switch ($path) {
                    '/'            { Send-HttpResponse -Context $context -StatusCode 200 -ContentType 'text/html; charset=utf-8' -Body $htmlBytes }
                    '/index.html'  { Send-HttpResponse -Context $context -StatusCode 200 -ContentType 'text/html; charset=utf-8' -Body $htmlBytes }
                    '/api/report'  { Send-HttpResponse -Context $context -StatusCode 200 -ContentType 'application/json; charset=utf-8' -Body $jsonBytes }
                    '/favicon.ico' { Send-HttpResponse -Context $context -StatusCode 204 -ContentType 'image/x-icon' -Body $favicon }
                    default {
                        $body = [Text.Encoding]::UTF8.GetBytes('{"error":"not found"}')
                        Send-HttpResponse -Context $context -StatusCode 404 -ContentType 'application/json; charset=utf-8' -Body $body
                    }
                }
            }
            catch {
                Write-Verbose "Request failed: $($_.Exception.Message)"
            }
        }
    }
    finally {
        try { if ($listener.IsListening) { $listener.Stop() } } catch { }
        try { $listener.Close() } catch { }
        Write-Host ''
        if ($autoStopped) {
            Write-Host "  Auto-shutdown after $AutoShutdownSeconds s. Port released." -ForegroundColor DarkGray
        }
        else {
            Write-Host '  Server stopped. Port released.' -ForegroundColor DarkGray
        }
    }
}

# ---------------------------------------------------------------------------
# 12. Pipeline
# ---------------------------------------------------------------------------

function Invoke-OceanScan {
    $admin = Test-IsAdmin

    Write-Phase -Activity 'Collecting system context' -Percent 4
    $system = Get-SystemInfo

    Write-Phase -Activity 'Indexing Minecraft jars' -Percent 14
    $roots = Get-MinecraftRoots -Extra $MinecraftPath
    $jars = Get-JarInventory -Roots $roots

    Write-Phase -Activity 'Dispatching hash verification' -Percent 26 -Status 'Modrinth + CurseForge (background)'
    $hashContext = Start-HashCheck -Jars $jars

    # Deep jar pass runs while the network lookups are in flight.
    Write-Phase -Activity 'Reading jar bytecode' -Percent 32 -Status 'constant pool + strings'
    Get-JarStringIntel -Inventory $jars

    Write-Phase -Activity 'Reading execution artefacts' -Percent 40
    $prefetch = Get-PrefetchData -InstanceStart $script:InstanceStart
    $null = Get-BamData -InstanceStart $script:InstanceStart
    $null = Get-UserAssistData -InstanceStart $script:InstanceStart
    $shim = Get-ShimCacheData -InstanceStart $script:InstanceStart

    Write-Phase -Activity 'Querying USN journal' -Percent 50
    $usn = Invoke-UsnQuery -TimeoutSeconds 20

    Write-Phase -Activity 'Scanning registry and DNS cache' -Percent 58
    $null = Get-RegistryArtifacts
    $dns = Get-DnsArtifacts
    $null = Get-BypassArtefacts

    Write-Phase -Activity 'Inspecting JVM and live processes' -Percent 66
    $java = Get-JavaArtifacts -GamePid $system.gamePid
    $intel = Get-ProcessIntel

    if ($NoMemoryScan) {
        Add-Provider -Name 'Memory' -Status 'skipped' -Note 'Disabled with -NoMemoryScan'
    }
    elseif ($system.gameRunning) {
        Write-Phase -Activity 'Reading process memory' -Percent 74
        Invoke-MemoryScan -Needles $script:CheatStrings -TimeoutMs 20000
    }
    else {
        Add-Provider -Name 'Memory' -Status 'skipped' -Note 'No javaw.exe running'
        Add-Finding -Category 'Suspicious logs' -Title 'Memory Scan Skipped' -Severity 'Info' `
            -Detail 'javaw.exe was not running, so no resident cheat strings could be verified.'
    }

    Write-Phase -Activity 'Resolving hash verification' -Percent 88
    $verified = Complete-HashCheck -Context $hashContext
    # Both jar passes run AFTER the memory scan so they can use resident-string
    # corroboration to decide whether a jar was actually loaded.
    Resolve-JarFindings -Inventory $jars -Verified $verified
    Resolve-JarStringFindings -Inventory $jars -Verified $verified

    # Prefetch gaps only become a Detection when another artefact proves the
    # missing programs actually ran on this machine.
    Resolve-PrefetchTamper

    Write-Phase -Activity 'Reviewing evidence confidence' -Percent 94
    $boot = Get-BootSequence -SystemInfo $system
    Resolve-FindingConfidence
    $verdict = Get-Verdict -Findings $script:Findings
    $report = New-Report -SystemInfo $system -Boot $boot -Verdict $verdict -JarInventory $jars `
        -JavaArtifacts $java -Prefetch $prefetch -Dns $dns -ProcessIntel $intel

    Write-Progress -Id 1 -Activity 'Ocean SS - screenshare scan' -Completed

    return [pscustomobject]@{ Report = $report; System = $system; Verdict = $verdict; Admin = $admin; Usn = $usn; Shim = $shim }
}

# ---------------------------------------------------------------------------
# 13. Entry point
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '  Ocean SS - Minecraft Screenshare Scanner' -ForegroundColor White
Write-Host "  pin $($script:PIN)  |  v$($script:ToolVersion)  |  read-only" -ForegroundColor DarkGray
Write-Host ''

if (-not (Test-IsAdmin)) {
    Write-Host '  [!] Running without elevation: BAM, USN journal and top-level prefetch may be unavailable.' -ForegroundColor Yellow
    Write-Host ''
}

$scan = Invoke-OceanScan

$json = $scan.Report | ConvertTo-Json -Depth 10 -Compress
# Keep the payload harmless inside a <script> block: escaping '<' kills the
# </script> breakout, and the two Unicode line separators are literal newlines
# to JavaScript and would otherwise terminate the statement.
$json = $json.Replace('<', '\u003c')
$json = $json.Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
$html = $script:DashboardHtml.Replace('__OCEAN_DATA__', $json)

try {
    $jsonPretty = $scan.Report | ConvertTo-Json -Depth 10
    Set-Content -LiteralPath $ReportPath -Value $jsonPretty -Encoding UTF8 -ErrorAction Stop
}
catch {
    Write-Warning "Report could not be written to $ReportPath : $($_.Exception.Message)"
}

$verdict = $scan.Verdict
$color = switch ($verdict.label) {
    'CHEATING'   { 'Red' }
    'SUSPICIOUS' { 'Yellow' }
    default      { 'Green' }
}

Write-Host ''
Write-Host '  ---------------------------------------------' -ForegroundColor DarkGray
Write-Host "   Verdict     : $($verdict.label)  ($($verdict.score)% risk)" -ForegroundColor $color
Write-Host "   Detections  : $($verdict.detections)  ($($verdict.confirmed) confirmed, $($verdict.sources) source(s))" -ForegroundColor Red
Write-Host "   Warnings    : $($verdict.warnings)" -ForegroundColor Yellow
Write-Host "   Legit checks: $($verdict.legit)" -ForegroundColor Green
if ($verdict.downgraded -gt 0) {
    Write-Host "   Heuristic rows demoted to warnings: $($verdict.downgraded)" -ForegroundColor DarkGray
}
Write-Host "   Report      : $ReportPath" -ForegroundColor DarkGray
Write-Host '  ---------------------------------------------' -ForegroundColor DarkGray
Write-Host ''

$script:ReportJson = $json
$script:ReportHtml = $html

if ($NoServer) {
    Write-Host '  -NoServer specified: collection finished, dashboard not started.' -ForegroundColor DarkGray
    Write-Host ''
    return
}

Start-WebServer -Port $Port -Html $html -Json $json -OpenBrowser:(-not $NoBrowser) `
    -KeepAlive:$KeepAlive -AutoShutdownSeconds $AutoShutdownSeconds

Write-Host ''
Write-Host "  Scan $($script:PIN) finished. Report saved to:" -ForegroundColor DarkGray
Write-Host "  $ReportPath" -ForegroundColor DarkGray
Write-Host ''

