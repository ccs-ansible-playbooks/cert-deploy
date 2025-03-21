#!/usr/bin/env -S pwsh -File
param (
    [Parameter(Mandatory=$false)]
    [String]$RunDir = $PSScriptRoot
);

$FROM_ADDRESS = "NetworkNotifications@centennialchristian.ca"
$FROM_NAME = "LetsEncrypt Cert Alert";
$EMAIL_TEMPLATE_PATH = Join-Path -Path $RunDir -ChildPath "failed-email.template.html.jinja";
$PLAYBOOK_DEPLOY_NAME = "cert-deploy-all.ansible.yml";
$PLAYBOOK_FETCH_NAME = "cert-fetch.ansible.yml";
$SECRETS_PATH = Join-Path -Path $RunDir -ChildPath "secrets/secrets.yml";
$TO_ADDRESS = "Notifications@centennialchristian.ca";


$prevDir = $PWD.Path;
cd $RunDir;
try {
    try {
        ./bin/Test-SecretsFile.ps1 -Path $SECRETS_PATH | Out-Null;
    } catch {
        # [Console]::Error.WriteLine($_.Exception.Message);
        ./bin/Send-EmailFailure.ps1 `
            -Details $_.Exception.Message `
            -FromAddress $FROM_ADDRESS `
            -FromName $FROM_NAME `
            -TemplatePath $EMAIL_TEMPLATE_PATH `
            -ToAddress $TO_ADDRESS `
     
        throw $_.Exception;
    }

    $fetchResults = ansible-playbook -u ansibleadmin -b "${PSScriptRoot}/${PLAYBOOK_FETCH_NAME}" 2>&1
    $fetchExitCode = $LASTEXITCODE;

    if ($fetchExitCode -ne 0) {
        ./bin/Send-EmailFailure.ps1 `
            -Details $fetchResults `
            -FromAddress $FROM_ADDRESS `
            -FromName $FROM_NAME `
            -TemplatePath $EMAIL_TEMPLATE_PATH `
            -ToAddress $TO_ADDRESS `
        
        Remove-Variable -Name fetchExitCode,fetchResults;
        throw "${fetchResults}";
    } else {
        $fetchResults;
    }
    Remove-Variable -Name fetchExitCode;

    if ($fetchResults | Select-String -SimpleMatch -Pattern 'New certificate files available.') {
        Remove-Variable -Name fetchExitCode,fetchResults;

        $deployResults = ansible-playbook -u ansibleadmin -b "${PSScriptRoot}/${PLAYBOOK_DEPLOY_NAME}" 2>&1
        $deployExitCode = $LASTEXITCODE;

        if ($deployExitCode -ne 0) {
            ./bin/Send-EmailFailure.ps1 `
                -Details $deployResults `
                -FromAddress $FROM_ADDRESS `
                -FromName $FROM_NAME `
                -TemplatePath $EMAIL_TEMPLATE_PATH `
                -ToAddress $TO_ADDRESS `

            Remove-Variable -Name deployResults,deployExitCode;
            throw "${deployExitCode}";
        } else {
            "`n${deployResults}";
        }
        Remove-Variable -Name deployExitCode,deployResults,fetchResults;
    } else {
        Write-Output "No new certificate files available.";
    }
} finally {
    cd $prevDir;
    Remove-Variable -Name FROM_ADDRESS,FROM_NAME,EMAIL_TEMPLATE_PATH,prevDir,PLAYBOOK_DEPLOY_NAME,PLAYBOOK_FETCH_NAME,SECRETS_PATH,TO_ADDRESS;
}