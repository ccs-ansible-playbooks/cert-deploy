#!/usr/bin/env -S pwsh -File 
param(
    [String]$Details,
    [String]$FromAddress,
    [String]$FromName,
    [String]$TemplatePath,
    [String]$ToAddress
);

Write-Host "Sending error email: ${Details}" -ForegroundColor Cyan;
return;

$addrJson = ip -br addr | `
    awk '$1 !~/^(lo|zt)/' | `
    column -JtN name,state,ipv4,ipv6 | `
    jq -Mc '.table' 

Get-Content -Path $TemplatePath -Raw |
    jinja2 `
        -D "computer_name=$(hostnamectl hostname)" `
        -D "fail_html_out=${details}" `
        -D "ip_address_list=${addrJson}" `
        -D "script_full_path=${PSCommandPath}" | `
    sendmail -f "${from_address}" -F "${from_name}" "${ToAddress}"
Remove-Variable -Name addrJson