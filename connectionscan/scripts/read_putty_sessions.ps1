<#
.SYNOPSIS
  Export PuTTY saved sessions from the current Windows user's registry hive.

.DESCRIPTION
  PuTTY stores saved sessions under HKCU:\Software\SimonTatham\PuTTY\Sessions.
  This script reads those keys and emits a stable JSON document for the
  weaverssh service-dock setup scanner. It does not read private key contents;
  it only reports configured paths and registry values.
#>
[CmdletBinding()]
param(
    [string]$RegistryRoot = 'HKCU:\Software\SimonTatham\PuTTY\Sessions',
    [switch]$IncludeRaw
)

$ErrorActionPreference = 'Stop'

function Decode-PuTTYSessionName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }
    try {
        return [System.Uri]::UnescapeDataString($Name)
    } catch {
        return $Name
    }
}

function Get-PropertyValue {
    param(
        [object]$Properties,
        [string]$Name,
        $Default = $null
    )
    if ($null -eq $Properties) {
        return $Default
    }
    $property = $Properties.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }
    return $property.Value
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
    $intValue = Convert-ToNullableInt $Value
    if ($null -eq $intValue) {
        return $null
    }
    return ($intValue -ne 0)
}

$result = [ordered]@{
    schema        = 'weaverssh-putty-sessions/v1'
    source        = 'windows-registry'
    registry_root = $RegistryRoot
    generated_at  = (Get-Date).ToUniversalTime().ToString('o')
    sessions      = @()
    errors        = @()
}

try {
    if (-not (Test-Path -LiteralPath $RegistryRoot)) {
        $result.errors += "registry_root_not_found:$RegistryRoot"
        $result | ConvertTo-Json -Depth 8
        exit 0
    }

    $keys = Get-ChildItem -LiteralPath $RegistryRoot -ErrorAction Stop | Sort-Object PSChildName
    foreach ($key in $keys) {
        try {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            $rawName = [string]$key.PSChildName
            $session = [ordered]@{
                name             = Decode-PuTTYSessionName $rawName
                raw_name         = $rawName
                source_path      = [string]$key.Name
                source_scope     = 'putty-registry'
                host_name        = [string](Get-PropertyValue $props 'HostName' '')
                user             = [string](Get-PropertyValue $props 'UserName' '')
                port             = Convert-ToNullableInt (Get-PropertyValue $props 'PortNumber' 22)
                protocol         = [string](Get-PropertyValue $props 'Protocol' 'ssh')
                identity_file    = [string](Get-PropertyValue $props 'PublicKeyFile' '')
                proxy_method     = Convert-ToNullableInt (Get-PropertyValue $props 'ProxyMethod' $null)
                proxy_host       = [string](Get-PropertyValue $props 'ProxyHost' '')
                proxy_port       = Convert-ToNullableInt (Get-PropertyValue $props 'ProxyPort' $null)
                proxy_user       = [string](Get-PropertyValue $props 'ProxyUsername' '')
                agent_forwarding = Convert-ToNullableBool (Get-PropertyValue $props 'AgentFwd' $null)
                x11_forwarding   = Convert-ToNullableBool (Get-PropertyValue $props 'X11Forward' $null)
                compression      = Convert-ToNullableBool (Get-PropertyValue $props 'Compression' $null)
                port_forwardings = [string](Get-PropertyValue $props 'PortForwardings' '')
            }
            if ($IncludeRaw) {
                $raw = [ordered]@{}
                foreach ($property in $props.PSObject.Properties) {
                    if ($property.Name -like 'PS*') {
                        continue
                    }
                    $raw[$property.Name] = $property.Value
                }
                $session['raw'] = $raw
            }
            $result.sessions += [pscustomobject]$session
        } catch {
            $result.errors += "session_read_failed:$($key.PSChildName):$($_.Exception.Message)"
        }
    }
} catch {
    $result.errors += "registry_read_failed:$($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 8
