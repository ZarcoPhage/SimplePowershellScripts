$baseKey = "Registry::HKEY_USERS"
$subPath = "Software\Fortinet\FortiClient\IPSec\Tunnels\Secure Internet Access\P1"

$userKeys = Get-ChildItem -Path $baseKey -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -notmatch "_Classes$" -and $_.PSChildName -match "S-1-5-21" }

$anyValid = $false

foreach ($userKey in $userKeys) {
    $sid = $userKey.PSChildName
    $fullPath = "Registry::HKEY_USERS\$sid\$subPath"

    if (Test-Path $fullPath) {
        $values = Get-ItemProperty -Path $fullPath -ErrorAction SilentlyContinue

        $hasPass    = -not [string]::IsNullOrEmpty($values.Pass)
        $savePassOn = ($values.SavePass -eq 1)

        Write-Host "Usuario SID: $sid"
        Write-Host "  Pass tiene valor : $hasPass"
        Write-Host "  SavePass = 1     : $savePassOn"
        Write-Host ""

        if ($hasPass -and $savePassOn) {
            $anyValid = $true
        }
    } else {
        Write-Host "Usuario SID: $sid"
        Write-Host "  Ruta no encontrada: $subPath"
        Write-Host ""
    }
}

if (-not $anyValid) {
    Write-Host "AVISO: Ningún usuario tiene Pass configurado y SavePass activado." -ForegroundColor Yellow
}