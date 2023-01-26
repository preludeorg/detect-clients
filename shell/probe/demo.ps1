[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Prelude Token")]
    [String]$preludeToken
)

function FromEnv { param ([string]$envVar, [string]$default)
    $envVal = [Environment]::GetEnvironmentVariable($envVar, "User")
    if ($envVal) { return $envVal } else { return $default }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$PRELUDE_API = FromEnv "PRELUDE_API" "https://api.preludesecurity.com"
$TEST_ID="b74ad239-2ddd-4b1e-b608-8397a43c7c54"

$dos = "windows-" + $Env:PROCESSOR_ARCHITECTURE

$TempFile = [System.IO.Path]::GetTempFileName() | Rename-Item -NewName { [System.IO.Path]::ChangeExtension($_, "exe") } -PassThru

$Headers = @{
    'token' = $preludeToken
    'dos' = $dos
    'id' = $TEST_ID
}

$symbols = [PSCustomObject] @{
    CHECKMARK = ([char]8730)
}

function CheckRelevance {
    Write-Host -ForegroundColor Green "`r`n[$($symbols.CHECKMARK)] Result: Success - server or workstation detected"
}

function DownloadTest {
    try {
        Invoke-WebRequest -URI $PRELUDE_API -UseBasicParsing -Headers $Headers -MaximumRedirection 1 -OutFile $TempFile -PassThru | Out-Null
    } catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        Write-Host -ForegroundColor Red "`r`n[!] Failed to download test. Http response code: $StatusCode"
        Exit 1
    }
    Write-Host -ForegroundColor Green "`r`n[$($symbols.CHECKMARK)] Wrote to temporary file: $TempFile"
}

function ExecuteTest {
    try {
        $p = Start-Process -FilePath $TempFile -Wait -NoNewWindow -PassThru
        if ($p.ExitCode -in 100,9,17,18,105,127 ) {
            Write-Host -ForegroundColor Green "`r`n[$($symbols.CHECKMARK)] Result: control test passed"
        } else {
            Write-Host -ForegroundColor Red "`r`n[!] Result: control test failed"
        }
        return $p.ExitCode
    } catch [System.InvalidOperationException] {
        Write-Host -ForegroundColor Red $_
        Write-Host -ForegroundColor Green "`r`n[$($symbols.CHECKMARK)] Result: control test passed"
        return 127
    } catch {
        Write-Host -ForegroundColor Red "`r`n[!] Unexpected error occurred:`r`n"
        Write-Host -ForegroundColor Red  $_
        return 1
    }
}

function ExecuteCleanup {
    try {
        $p = Start-Process -FilePath $TempFile -ArgumentList "clean" -Wait -NoNewWindow -PassThru
        if ($p.ExitCode -eq 100 ) {
            Write-Host -ForegroundColor Green "`r`n[$($symbols.CHECKMARK)] Clean up is complete"
        } else {
            Write-Host -ForegroundColor Red "`r`n[!] Clean up failed"
        }
    } catch [System.InvalidOperationException] {
        Write-Host -ForegroundColor Red $_
        Write-Host -ForegroundColor Red "`r`n[!] Clean up failed"
    } catch {
        Write-Host -ForegroundColor Red "`r`n[!] Unexpected error occurred:`r`n"
        Write-Host -ForegroundColor Red  $_
    }
}

function PostResults {
    param([string]$testresult)
    $Headers.dat = $TEST_ID + ":" + $testresult
    Invoke-WebRequest -URI $PRELUDE_API -UseBasicParsing -Headers $Headers -MaximumRedirection 1 | Out-Null
}

Write-Host "
###########################################################################################################

Will your computer quarantine a malicious Office document?

Malicious files are used to gain entry and conduct cyberattacks against corporate systems through seemingly
innocuous email attachments or direct downloads. For example - a malicious macro was used by the BlueNoroff
group in a ransomware attack (Dec. 2022).

This test will attempt to download a malicious file to your disk (a macro enabled excel file generated with
Msfvenom) in order to see how your machine will respond. Since downloading malicious files increases your
risk by opening you up to further attack, the ability to detect and quarantine any potentially harmful files
as quickly as possible is an important part of maintaining a proper security posture.

This is a Verified Security Test (VST) Developed by Prelude Research Inc.

[+] Applicable CVE(s): CVE-2017-0199
[+] ATT&CK mappings: T1204.002

###########################################################################################################
"
Read-Host -Prompt "Press ENTER to continue"

Write-Host "Starting test at: $(Get-Date -UFormat %T)

-----------------------------------------------------------------------------------------------------------
[0] Conducting relevance test"
Start-Sleep -Seconds 3
CheckRelevance

Write-Host "-----------------------------------------------------------------------------------------------------------
[1] Downloading test"
DownloadTest

Write-Host "-----------------------------------------------------------------------------------------------------------
[2] Executing test
"
Start-Sleep -Seconds 3
$TestResult = ExecuteTest

Write-Host "-----------------------------------------------------------------------------------------------------------
[3] Running cleanup
"
Start-Sleep -Seconds 3
if ($TestResult -in 100,9,17,18,105,127) {
    Write-Host -ForegroundColor Green "`r`n[$($symbols.CHECKMARK)] Clean up is complete"
} else {
    ExecuteCleanup
}

PostResults $TestResult

Write-Host "
###########################################################################################################
"

if ($TestResult -in 100,9,17,18,105,127 ) {
    Write-Host -ForegroundColor Green "[$($symbols.CHECKMARK)] Good job! Your computer detected and responded to a malicious Office document dropped on the disk"
} elseif ($TestResult -eq 101) {
    Write-Host -ForegroundColor Red "[!] This test was able to verify the existence of this vulnerability on your machine, as well as drop a malicious
Office document on the disk. If you have security controls in place that you suspect should have protected your
host, please review the logs"
} else {
    Write-Host -ForegroundColor Red "[!] This test encountered an unexpected error during execution. Please try again"
}

Write-Host "
###########################################################################################################

[*] Return to https://platform.preludesecurity.com to view your results
"