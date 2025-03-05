#!/usr/bin/env -S pwsh -File 
param([String]$Path);
 
if (-not (Test-Path -Path $Path -EA SilentlyContinue)) {
    
    throw @"
The file '${Path}' is missing.
Please use '${Path}.example' as a reference to create the file.
This file must have read + write permissions for user only. Use the following
command to set permissions on the new file after it is created:
sudo chmod 0600 "${Path}"
"@
}

$posixPermissions = Get-Item -Path $Path | `
    Select-Object -ExpandProperty UnixMode

if ( -not ($posixPermissions -match ".[rwxXsS\-]{3}-{6}")) {
    throw @"
Incorrect permissions set: ${posixPermissions} .
This file must have read + write permissions for user only. Use the following
command to set permissions on the file:
sudo chmod 0600 "${Path}"
"@
}

return $true;
