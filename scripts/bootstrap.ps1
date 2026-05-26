param()

$ErrorActionPreference = 'Stop'

$rootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$venvDir = Join-Path $rootDir 'venv'

$python = $null
foreach ($candidate in @('py', 'python')) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $python = $candidate
        break
    }
}

if (-not $python) {
    throw 'Python 3 is required but was not found on PATH.'
}

if (-not (Test-Path $venvDir)) {
    & $python -m venv $venvDir
}

$activateScript = Join-Path (Join-Path $venvDir 'Scripts') 'Activate.ps1'
. $activateScript

python -m pip install --upgrade pip setuptools wheel
python -m pip install -r (Join-Path $rootDir 'requirements.txt')

$missingTools = New-Object System.Collections.Generic.List[string]

function Test-Command([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-AnyPath([string[]]$Paths) {
    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        if (Test-Path $path) {
            return $true
        }
    }

    return $false
}

if (-not (Test-Command 'tshark')) { $missingTools.Add('tshark') }
if (-not (Test-Command 'fls')) { $missingTools.Add('fls') }
if (-not (Test-Command 'perl')) { $missingTools.Add('perl') }
if (-not (Test-Command 'log2timeline.py') -and -not (Test-Command 'log2timeline')) {
    $missingTools.Add('log2timeline.py/log2timeline')
}

$regripperCandidates = @(
    $env:REGRIPPER_PATH,
    (Join-Path (Join-Path $HOME 'regripper') 'rip.pl'),
    (Join-Path (Join-Path $HOME 'RegRipper3.0') 'rip.pl'),
    (Join-Path (Join-Path $HOME 'RegRipper') 'rip.pl'),
    (Join-Path (Join-Path (Join-Path $HOME 'Desktop') 'RegRipper3.0') 'rip.pl')
)

if (-not (Test-AnyPath $regripperCandidates)) {
    $missingTools.Add('RegRipper rip.pl')
}

if ($missingTools.Count -gt 0) {
    Write-Host ''
    Write-Host 'Python dependencies are installed, but these live-run tools are still missing:'
    foreach ($tool in $missingTools) {
        Write-Host "  - $tool"
    }
    Write-Host ''
    Write-Host 'Install them separately, then re-run this script if you want to verify availability.'
}

Write-Host ''
Write-Host 'Setup complete. Activate the environment with: . .\venv\Scripts\Activate.ps1'