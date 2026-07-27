<#
.SYNOPSIS
  Export PuTTY sessions through the PSPuTTYCfg PowerShell module.

.DESCRIPTION
  PSPuTTYCfg can import PuTTY sessions from the Windows registry or from a
  JSON configuration directory such as $HOME\PuTTY. This script normalizes the
  imported sessions into the same metadata shape used by the weaverssh setup
  scanner. It reports configuration metadata only and never reads private key
  contents.
#>
[CmdletBinding(DefaultParameterSetName = 'Registry')]
param(
    [Parameter(ParameterSetName = 'Path')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Registry')]
    [switch]$Registry
)

$ErrorActionPreference = 'Stop'

function Get-PropertyValue {
    param(
        [object]$Object,
        [string[]]$Names,
        $Default = $null
    )
    if ($null -eq $Object) {
        return $Default
    }
    foreach ($Name in $Names) {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property) {
            return $property.Value
        }
    }
    foreach ($property in $Object.PSObject.Properties) {
        foreach ($Name in $Names) {
            if ($property.Name -ieq $Name) {
                return $property.Value
            }
        }
    }
    return $Default
}

function Get-NestedPropertyValue {
    param(
        [object]$Object,
        [string[][]]$Paths,
        $Default = $null
    )
    foreach ($PathParts in $Paths) {
        $cursor = $Object
        $found = $true
        foreach ($Part in $PathParts) {
            $next = Get-PropertyValue -Object $cursor -Names @($Part) -Default $null
            if ($null -eq $next) {
                $found = $false
                break
            }
            $cursor = $next
        }
        if ($found) {
            return $cursor
        }
    }
    return $Default
}

function Convert-ToNullableInt {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') {
        return $null
    }
    try {
        return [int]$Value
    } catch {
        return $null
    }
}

function Convert-ToNullableBool {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') {
        return $null
    }
    if ($Value -is [bool]) {
        return [bool]$Value
    }
    $text = ([string]$Value).Trim().ToLowerInvariant()
    if ($text -in @('1', 'true', 'yes', 'on', 'enabled')) {
        return $true
    }
    if ($text -in @('0', 'false', 'no', 'off', 'disabled')) {
        return $false
    }
    return $null
}

function Convert-ToStringList {
    param($Value)
    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [array]) {
        return [string]::Join(',', @($Value | ForEach-Object { [string]$_ }))
    }
    return [string]$Value
}

$result = [ordered]@{
    schema       = 'weaverssh-psputtycfg-sessions/v1'
    source       = 'PSPuTTYCfg'
    path         = $Path
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    sessions     = @()
    errors       = @()
}

try {
    Import-Module PSPuTTYCfg -ErrorAction Stop

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $rawSessions = Import-PuTTYSession -Path $Path
        $sourceScope = 'psputtycfg-json'
        $sourcePath = $Path
    } else {
        $rawSessions = Import-PuTTYSession -Registry
        $sourceScope = 'psputtycfg-registry'
        $sourcePath = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
    }

    foreach ($raw in @($rawSessions)) {
        try {
            $connection = Get-PropertyValue -Object $raw -Names @('connection')
            $host = Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'host'), @('connection', 'HostName')) -Default ''
            $name = Get-PropertyValue -Object $raw -Names @('name', 'session', 'sessionName', 'SessionName') -Default ''
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = [string]$host
            }
            $forwardedPorts = Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'ssh', 'tunnels', 'forwardedPorts'), @('connection', 'ssh', 'tunnels', 'PortForwardings')) -Default $null
            $session = [ordered]@{
                name             = [string]$name
                raw_name         = [string]$name
                source_path      = [string]$sourcePath
                source_scope     = $sourceScope
                host_name        = [string]$host
                user             = [string](Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'data', 'username'), @('connection', 'data', 'UserName')) -Default '')
                port             = Convert-ToNullableInt (Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'port'), @('connection', 'PortNumber')) -Default 22)
                protocol         = [string](Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'protocol'), @('connection', 'Protocol')) -Default 'ssh')
                identity_file    = [string](Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'ssh', 'auth', 'authKeyFile'), @('connection', 'ssh', 'auth', 'PublicKeyFile')) -Default '')
                proxy_type       = [string](Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'proxy', 'type'), @('connection', 'proxy', 'ProxyType')) -Default '')
                proxy_host       = [string](Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'proxy', 'host'), @('connection', 'proxy', 'ProxyHost')) -Default '')
                proxy_port       = Convert-ToNullableInt (Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'proxy', 'port'), @('connection', 'proxy', 'ProxyPort')) -Default $null)
                proxy_user       = [string](Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'proxy', 'username'), @('connection', 'proxy', 'ProxyUsername')) -Default '')
                agent_forwarding = Convert-ToNullableBool (Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'ssh', 'auth', 'agentForwarding'), @('connection', 'ssh', 'auth', 'AgentFwd')) -Default $null)
                x11_forwarding   = Convert-ToNullableBool (Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'ssh', 'x11', 'x11Forwarding'), @('connection', 'ssh', 'x11', 'X11Forward')) -Default $null)
                compression      = Convert-ToNullableBool (Get-NestedPropertyValue -Object $raw -Paths @(@('connection', 'ssh', 'compression'), @('connection', 'ssh', 'Compression')) -Default $null)
                port_forwardings = Convert-ToStringList $forwardedPorts
            }
            $result.sessions += [pscustomobject]$session
        } catch {
            $result.errors += "session_normalize_failed:$($_.Exception.Message)"
        }
    }
} catch {
    $result.errors += "psputtycfg_failed:$($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 32
