#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Obtiene el primer login exitoso por usuario por dia en los ultimos 6 meses.

.DESCRIPTION
    Consulta el Event Log de Seguridad de Windows (Event ID 4624) y devuelve
    unicamente el primer inicio de sesion exitoso de cada usuario por cada dia,
    cubriendo los ultimos 6 meses desde la fecha de ejecucion.

.PARAMETER ExportCSV
    Ruta opcional para exportar los resultados a un archivo CSV.

.PARAMETER ExportHTML
    Ruta opcional para exportar los resultados a un archivo HTML.

.EXAMPLE
    .\Get-LoginHistory.ps1
    .\Get-LoginHistory.ps1 -ExportCSV "C:\Reportes\logins.csv"
    .\Get-LoginHistory.ps1 -ExportHTML "C:\Reportes\logins.html"
#>

[CmdletBinding()]
param (
    [string]$ExportCSV  = "",
    [string]$ExportHTML = ""
)

# Tipos de logon
$LogonTypes = @{
    2  = "Interactivo (local)"
    3  = "Red"
    4  = "Batch"
    5  = "Servicio"
    7  = "Desbloqueo"
    8  = "Red (texto plano)"
    9  = "Nuevas credenciales"
    10 = "Remoto Interactivo (RDP)"
    11 = "Interactivo en cache"
    12 = "Remoto en cache"
    13 = "Desbloqueo en cache"
}

# ---------------------------------------------
# Rango: ultimos 6 meses
# ---------------------------------------------
$EndDate   = Get-Date
$StartDate = $EndDate.AddMonths(-6)

Write-Host ""
Write-Host "+==========================================================+" -ForegroundColor Cyan
Write-Host "|   PRIMER LOGIN DIARIO POR USUARIO - ULTIMOS 6 MESES     |" -ForegroundColor Cyan
Write-Host "+==========================================================+" -ForegroundColor Cyan
Write-Host "|  Equipo : $($env:COMPUTERNAME)"                             -ForegroundColor Cyan
Write-Host "|  Desde  : $($StartDate.ToString('dd/MM/yyyy HH:mm:ss'))"   -ForegroundColor Cyan
Write-Host "|  Hasta  : $($EndDate.ToString('dd/MM/yyyy HH:mm:ss'))"     -ForegroundColor Cyan
Write-Host "+==========================================================+" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------
# Verificar acceso al Event Log
# ---------------------------------------------
try {
    Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "No se puede acceder al Event Log de Seguridad."
    Write-Warning "Ejecuta el script como Administrador."
    exit 1
}

# ---------------------------------------------
# Consultar solo logins exitosos (4624)
# ---------------------------------------------
Write-Host "Consultando Event Log (esto puede tardar unos minutos para 6 meses de datos)..." -ForegroundColor Yellow

$FilterHash = @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $StartDate
    EndTime   = $EndDate
}

try {
    $RawEvents = Get-WinEvent -FilterHashtable $FilterHash -ErrorAction Stop
    Write-Host "Eventos 4624 encontrados: $($RawEvents.Count)" -ForegroundColor Green
} catch [System.Exception] {
    if ($_.Exception.Message -match "No events were found") {
        Write-Host "No se encontraron eventos en el periodo indicado." -ForegroundColor Yellow
        exit 0
    } else {
        Write-Error "Error al consultar eventos: $_"
        exit 1
    }
}

# ---------------------------------------------
# Procesar y parsear eventos
# ---------------------------------------------
Write-Host "Procesando eventos..." -ForegroundColor Yellow

$AllLogins = foreach ($Event in $RawEvents) {
    try {
        $XML  = [xml]$Event.ToXml()
        $Data = $XML.Event.EventData.Data

        $TargetUser   = ($Data | Where-Object { $_.Name -eq 'TargetUserName'   }).'#text'
        $SubjectUser  = ($Data | Where-Object { $_.Name -eq 'SubjectUserName'  }).'#text'
        $LogonTypeRaw = ($Data | Where-Object { $_.Name -eq 'LogonType'        }).'#text'
        $WorkStation  = ($Data | Where-Object { $_.Name -eq 'WorkstationName'  }).'#text'
        $IPAddress    = ($Data | Where-Object { $_.Name -eq 'IpAddress'        }).'#text'

        # Usuario efectivo
        $UserName = if ($TargetUser -and $TargetUser -ne '-') { $TargetUser }
                    elseif ($SubjectUser -and $SubjectUser -ne '-') { $SubjectUser }
                    else { $null }

        # Filtrar cuentas de sistema
        if (-not $UserName) { continue }
        if ($UserName -match '^\$|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$|^DWM-|^UMFD-|^-$') { continue }

        # Tipo de logon legible
        $LogonTypeInt  = if ($LogonTypeRaw) { [int]$LogonTypeRaw } else { 0 }
        $LogonTypeDesc = if ($LogonTypes.ContainsKey($LogonTypeInt)) {
                             "$LogonTypeInt - $($LogonTypes[$LogonTypeInt])"
                         } else { "$LogonTypeInt" }

        [PSCustomObject]@{
            Fecha       = $Event.TimeCreated
            Dia         = $Event.TimeCreated.ToString('yyyy-MM-dd')
            Usuario     = $UserName
            TipoLogon   = $LogonTypeDesc
            Equipo      = if ($WorkStation -and $WorkStation -ne '-') { $WorkStation } else { $env:COMPUTERNAME }
            DireccionIP = if ($IPAddress   -and $IPAddress   -ne '-') { $IPAddress   } else { "Local" }
        }
    } catch {
        continue
    }
}

# ---------------------------------------------
# Filtrar: primer login por usuario por dia
# ---------------------------------------------
Write-Host "Filtrando primer login por usuario por dia..." -ForegroundColor Yellow

$FirstLoginPerDay = $AllLogins |
    Sort-Object Fecha |
    Group-Object { "$($_.Dia)|$($_.Usuario)" } |
    ForEach-Object {
        $_.Group | Sort-Object Fecha | Select-Object -First 1
    } |
    Sort-Object Fecha -Descending

Write-Host "Registros unicos (primer login diario): $($FirstLoginPerDay.Count)" -ForegroundColor Green

# ---------------------------------------------
# Mostrar resumen por usuario
# ---------------------------------------------
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  RESUMEN POR USUARIO (dias con login)"    -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$FirstLoginPerDay |
    Group-Object Usuario |
    ForEach-Object {
        $diasUnicos  = ($_.Group | Select-Object -ExpandProperty Dia | Sort-Object -Unique).Count
        $primerLogin = ($_.Group | Sort-Object Fecha | Select-Object -First 1).Fecha
        $ultimoLogin = ($_.Group | Sort-Object Fecha -Descending | Select-Object -First 1).Fecha
        [PSCustomObject]@{
            Usuario     = $_.Name
            DiasConLogin = $diasUnicos
            PrimerLogin = $primerLogin.ToString('dd/MM/yyyy HH:mm:ss')
            UltimoLogin = $ultimoLogin.ToString('dd/MM/yyyy HH:mm:ss')
        }
    } |
    Sort-Object DiasConLogin -Descending |
    Format-Table -AutoSize

# ---------------------------------------------
# Mostrar detalle
# ---------------------------------------------
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  DETALLE - PRIMER LOGIN DIARIO ($($FirstLoginPerDay.Count) registros)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$FirstLoginPerDay |
    Select-Object Fecha, Usuario, TipoLogon, DireccionIP, Equipo |
    Format-Table -AutoSize

# ---------------------------------------------
# Exportar CSV
# ---------------------------------------------
if ($ExportCSV -ne "") {
    try {
        $FirstLoginPerDay | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
        Write-Host "[OK] Exportado a CSV: $ExportCSV" -ForegroundColor Green
    } catch {
        Write-Warning "No se pudo exportar a CSV: $_"
    }
}

# ---------------------------------------------
# Exportar HTML
# ---------------------------------------------
if ($ExportHTML -ne "") {
    try {
        $HTMLHeader = @"
<style>
  body  { font-family: Segoe UI, sans-serif; font-size: 13px; background:#1a1a2e; color:#e0e0e0; margin:20px; }
  h1    { color:#00d4ff; }
  h2    { color:#a0c4ff; border-bottom:1px solid #444; padding-bottom:4px; margin-top:30px; }
  p     { color:#aaa; }
  table { border-collapse:collapse; width:100%; margin-bottom:30px; }
  th    { background:#0f3460; color:#fff; padding:8px 12px; text-align:left; }
  td    { padding:6px 12px; border-bottom:1px solid #2a2a3e; }
  tr:hover { background:#16213e; }
</style>
<h1>Primer Login Diario por Usuario</h1>
<p>Equipo: $($env:COMPUTERNAME) | Periodo: $($StartDate.ToString('dd/MM/yyyy')) hasta $($EndDate.ToString('dd/MM/yyyy'))</p>
"@

        $ResumenHTML = $FirstLoginPerDay |
            Group-Object Usuario |
            ForEach-Object {
                $dias = ($_.Group | Select-Object -ExpandProperty Dia | Sort-Object -Unique).Count
                [PSCustomObject]@{
                    Usuario      = $_.Name
                    DiasConLogin = $dias
                    PrimerLogin  = ($_.Group | Sort-Object Fecha | Select-Object -First 1).Fecha.ToString('dd/MM/yyyy HH:mm:ss')
                    UltimoLogin  = ($_.Group | Sort-Object Fecha -Descending | Select-Object -First 1).Fecha.ToString('dd/MM/yyyy HH:mm:ss')
                }
            } |
            Sort-Object DiasConLogin -Descending |
            ConvertTo-Html -Fragment -PreContent "<h2>Resumen por Usuario</h2>"

        $DetalleHTML = $FirstLoginPerDay |
            Select-Object Fecha, Usuario, TipoLogon, DireccionIP, Equipo |
            ConvertTo-Html -Fragment -PreContent "<h2>Detalle de Primer Login Diario</h2>"

        ConvertTo-Html -Head $HTMLHeader -Body "$ResumenHTML $DetalleHTML" |
            Out-File -FilePath $ExportHTML -Encoding UTF8

        Write-Host "[OK] Exportado a HTML: $ExportHTML" -ForegroundColor Green
    } catch {
        Write-Warning "No se pudo exportar a HTML: $_"
    }
}

Write-Host ""
Write-Host "Script finalizado." -ForegroundColor Green
