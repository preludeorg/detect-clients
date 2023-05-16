[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Execute { 
    Param([String]$File)

    try {
        $R = (Start-Process -FilePath $File -Wait -NoNewWindow -PassThru).ExitCode
        $Code = if (Test-Path $File) {$R} Else {127}
        return $Code
    } catch [System.UnauthorizedAccessException] {
        return 126
    } catch [System.InvalidOperationException] {
        return 127
    } catch {
        return 1
    }
}

function FromEnv { param ([string]$envVar, [string]$default)
    $envVal = [Environment]::GetEnvironmentVariable($envVar, "Machine")
    if ($envVal) { return $envVal } else { return $default }
}

$Dir = FromEnv "PRELUDE_DIR" ".vst"
$Sleep = FromEnv "PRELUDE_SLEEP" 14440
$CA = "prelude-account-us1-us-west-1.s3.amazonaws.com"

$Api = "https://api.preludesecurity.com"
$Dos = "windows-$Env:PROCESSOR_ARCHITECTURE"
$Dat = ""

while ($true) {
    try {
        $Vst = New-Item -Path "$Dir\$(New-Guid).exe" -Force
        $Headers = @{
            'token' = FromEnv "PRELUDE_TOKEN"
            'dos' = $Dos
            'dat' = $Dat
            'version' = "1.1"
        }

        $Redirect = Invoke-WebRequest -URI $Api -UseBasicParsing -Headers $Headers -MaximumRedirection 0
        if ($Redirect.Headers.Location -contains "upgrade") {
            Write-Output "[P] Upgrade required"
            exit 1
        }

        $Response = Invoke-WebRequest -URI $Redirect.Headers.Location -UseBasicParsing -Headers $Headers -PassThru
        $Test = $Response.BaseResponse.ResponseUri.AbsolutePath.Split("/")[-1].Split("_")[0]

        if ($Test) {
            if ($CA -eq $Response.BaseResponse.ResponseUri.Authority) {
                Write-Output "[P] Running $Test [$Vst]"
                $Code = Execute $Vst
                $Dat = "${Test}:$Code"
            }
        } else {
            throw "Tests completed"
        }
    } catch {
        Write-Output $_.Exception
        $Dat = ""
        Remove-Item $Dir -Force -Recurse -ErrorAction SilentlyContinue
        Start-Sleep -Seconds $Sleep
    }
}
