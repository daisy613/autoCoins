### author:  Daisy
### discord: Daisy#2718
### site:    https://github.com/daisy613/autoCoins
### issues:  https://github.com/daisy613/autoCoins/issues
### tldr:    This Powershell script dynamically controls the coin list in WickHunter bot to blacklist\un-blacklist coins based on proximity to ATH, 1hr/24hr price change and minimum coin age.
### Changelog:
### * settings can be changed without restarting script - they will be read upon the next refresh cycle
### * added current coin name to the progress bar
### * fixed a 1hr/24hr logic bug
### * removed redundant date output from console/logfile
### * set execution policy

$path = Split-Path $MyInvocation.MyCommand.Path

### run powershell as admin$settings.discord
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments -WorkingDirectory $path
    Break
}

$version = "v1.2.4a"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
$host.UI.RawUI.WindowTitle = "AutoCoins $($version) - $($path)"
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force -Confirm:$false -Scope CurrentUser

If (-not (Get-Module -Name "PSSQLite")) {
    Install-Module "PSSQLite" -Scope CurrentUser
    Import-Module "PSSQLite" -DisableNameChecking -Verbose:$false | Out-Null
}

$settings = gc "$($path)\autoCoins.json" | ConvertFrom-Json
if (!($settings)) { write-log -string "Cannot find $($path)\autoCoins.json file!" -color "DarkRed"; sleep 30 ; exit }
$dataSource = "$($path)\storage.db"
$logfile = "$($path)\autoCoins.log"

######################################################################################################

Function write-log {
    Param ([string]$string,$color="Yellow")
    $date = Get-Date -Format "$($version) yyyy-MM-dd HH:mm:ss"
    Write-Host "[$date] $string" -ForegroundColor $color
    Add-Content $Logfile -Value "[$date] $string"
}

function checkLatest () {
    $repo = "daisy613/autoCoins"
    $releases = "https://api.github.com/repos/$repo/releases"
    $latestTag = [array](Invoke-WebRequest $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name
    $youngerVer = ($version, $latestTag | Sort-Object)[-1]
    if ($latestTag -and $version -ne $youngerVer) {
        write-log -string "Your version of $($repo) [$($version)] is outdated. Newer version [$($latestTag)] is available: https://github.com/$($repo)/releases/tag/$($latestTag)" -color "Red"
    }
}

function betterSleep () {
    Param ($seconds,$message)
    $doneDT = (Get-Date).AddSeconds($seconds)
    while($doneDT -gt (Get-Date)) {
        $minutes = [math]::Round(($seconds / 60),2)
        $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
        $percent = ($seconds - $secondsLeft) / $seconds * 100
        Write-Progress -Activity "$($message)" -Status "Sleeping $($minutes) minutes..." -SecondsRemaining $secondsLeft -PercentComplete $percent
        [System.Threading.Thread]::Sleep(500)
    }
    Write-Progress -Activity "$($message)" -Status "Sleeping $($minutes) minutes..." -SecondsRemaining 0 -Completed
}

function sendDiscord () {
    Param($webHook,$message)
    $hookUrl = $webHook
    if ($hookUrl) {
        $content = $message
        $payload = [PSCustomObject]@{
            content = $content
        }
        Invoke-RestMethod -Uri $hookUrl -Method Post -Body ($payload | ConvertTo-Json) -ContentType 'Application/Json'
    }
}

function Invoke-RestMethodCustom ($uri,$proxy,$proxyUser,$proxyPass) {
    if ($proxy -ne "http://PROXYIP:PROXYPORT" -and $proxy -ne "" -and $proxyUser -eq "") {
        $result = Invoke-RestMethod -Uri $uri -Proxy $proxy
    } elseif ($proxy -ne "http://PROXYIP:PROXYPORT" -and $proxy -ne "" -and $proxyUser -ne "") {
        [System.Security.SecureString]$proxyPassSec = ConvertTo-SecureString $proxyPass -AsPlainText -Force
        $proxCred = new-object -typename System.Management.Automation.PSCredential -argumentlist ($proxyUser, $proxyPassSec)
        $result = Invoke-RestMethod -Uri $uri -Proxy $proxy -ProxyCredential $proxCred
    } else {
        $result = Invoke-RestMethod -Uri $uri
    }
    return $result
}

function getSymbols () {
    $uri = "https://fapi.binance.com/fapi/v1/exchangeInfo"
    $symbols = ((Invoke-RestMethodCustom $uri $settings.proxy $settings.proxyUser $settings.proxyPass).symbols).symbol | Sort-Object
    return $symbols
}

# https://binance-docs.github.io/apidocs/futures/en/#kline-candlestick-data
# https://binance-docs.github.io/apidocs/futures/en/#24hr-ticker-price-change-statistics
function getInfo () {
    Param($max1hrPercent,$max24hrPercent,$minAthPercent,$minAge)
    $symbols = getSymbols
    $coins = @()
    $quarantined = @()
    $objects = @()
    $count = 0
    $uri = "https://fapi.binance.com/fapi/v1/ticker/24hr"
    $24HrPrices = (Invoke-RestMethodCustom $uri $settings.proxy $settings.proxyUser $settings.proxyPass) | select symbol,priceChangePercent
    $openPositions = (Invoke-SqliteQuery -DataSource $DataSource -Query "SELECT symbol FROM [Order] WHERE State = 'New'").Symbol
    $symbols = $symbols | ? { $_ -notin $settings.blacklist }
    foreach ($symbol in $symbols) {
        $count++
        $percentDone = $count / $symbols.length * 100
        Write-Progress -Activity "Processing ..." -Status "Symbol: $($symbol) [$($count)/$($symbols.length)]" -PercentComplete $percentDone
        # calculate the 1hr price change
        $uri = "https://fapi.binance.com/fapi/v1/klines?symbol=$($symbol)&interval=1m&limit=60"
        $1hrPrices = (Invoke-RestMethodCustom $uri $settings.proxy $settings.proxyUser $settings.proxyPass) | % { $_[1] }
        $1hrPercentCurr = [math]::Abs((($1hrPrices[-1] - $1hrPrices[0]) * 100) / $1hrPrices[-1])
        $24hrPercentCurr = [math]::Abs(($24HrPrices | ? { $_.symbol -eq $symbol}).priceChangePercent)
        #calculate ATH percentage
        $uri = "https://fapi.binance.com/fapi/v1/klines?symbol=$($symbol)&interval=1M&limit=500"
        $ath = [decimal] ((Invoke-RestMethodCustom $uri $settings.proxy $settings.proxyUser $settings.proxyPass) | % { $_[2] } | measure -Maximum).Maximum
        $athPercentCurr = (($ath - $1hrPrices[-1]) * 100 / $ath)
        # calculate age
        $uri = "https://fapi.binance.com/fapi/v1/klines?limit=1500&symbol=$($symbol)&interval=1d"
        $age = (Invoke-RestMethodCustom $uri $settings.proxy $settings.proxyUser $settings.proxyPass).length
        [array]$objects += [PSCustomObject][object]@{
            "symbol"      = $symbol
            "perc1hr"     = $(if ($1hrPercentCurr -lt $max1hrPercent) { "PASS" } else { "FAIL" })
            "perc1hrVal"  = [math]::Round($1hrPercentCurr,2)
            "perc24hr"    = $(if ($24hrPercentCurr -lt $max24hrPercent) { "PASS" } else { "FAIL" })
            "perc24hrVal" = [math]::Round($24hrPercentCurr,2)
            "Ath"         = $(if ($athPercentCurr -gt $minAthPercent) { "PASS" } else { "FAIL" })
            "AthVal"      = [math]::Round($ath,2)
            "Age"         = $(if ($age -gt $minAge) { "PASS" } else { "FAIL" })
            "AgeVal"      = $age
            "Open"        = $(if ($symbol -notin $openPositions) { "PASS" } else { "FAIL" })
        }
    }
    $quarantined   = ($objects | ? { ($_.perc1hr -eq "FAIL" -or $_.perc24hr -eq "FAIL" -or $_.Ath -eq "FAIL" -or $_.Age -eq "FAIL") -and $_.Open -eq "PASS" }).symbol | sort
    $permittedCurr = ((Invoke-SqliteQuery -DataSource $dataSource -Query "SELECT * FROM Instrument")  | ? {$_.IsPermitted -eq 1 }).symbol | sort
    $permitted     = $symbols | ? {$_ -notin  $quarantined} | sort
    $unQuarantined = $permitted | ? {$_ -notin  $permittedCurr} | sort
    $objects | select * | ft -autosize | out-file -append $logfile
    write-log -string "Quarantined: $($quarantined -join ', ')" -color "yellow"
    $message = "**QUARANTINED**: $($quarantined -join ', ')"
    sendDiscord $discord $message
    if ($unQuarantined) {
        write-log -string "Un-Quarantined: $($unQuarantined -join ', ')" -color "yellow"
        $message = "**UNQUARANTINED**: $($unQuarantined -join ', ')"
        sendDiscord $discord $message
    }
    $openNotQuarantined = ($objects | ? { $_.Open -eq "FAIL" -and ($_.perc1hr -eq "FAIL" -or $_.perc24hr -eq "FAIL" -or $_.Ath -eq "FAIL" -or $_.Age -eq "FAIL") }).symbol
    if ($openNotQuarantined) {
        write-log -string "Open Positions (could not quarantine): $($openNotQuarantined -join ', ')" -color "yellow"
        $message = "**OPEN POSITIONS - NOT QUARANTINED**: $($openNotQuarantined -join ', ')"
        sendDiscord $discord $message
    }
    return $permitted
}

write-host "`n`n`n`n`n`n`n`n`n`n"
checkLatest

while ($true) {
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $settings = gc "$($path)\autoCoins.json" | ConvertFrom-Json
    if ($settings.proxy -ne "http://PROXYIP:PROXYPORT" -and $settings.proxy -ne "") {
        write-log -string "Using proxy $($settings.proxy)" -color "Cyan"
    }
    write-log -string "Calculating coin list ..." -color "Green"
    $coinList = getInfo $settings.max1hrPercent $settings.max24hrPercent $settings.minAthPercent $settings.minAge
    ### get currently enabled coins
    if ($coinList) {
        # write-log -string "Backing up your current WH database..." -color "Green"
        cp $dataSource "$($dataSource).bak" -force
        ### update the coins in the database
        $coins = @()
        foreach ($item in $coinList) {
            $coin = @()
            $coin = [PSCustomObject]@{
                Symbol = $item
                IsPermitted = 1
                IsNonDeaultSettigs = 0
            }
            $coins += $coin
        }
        $query = 'DROP TABLE IF EXISTS "Instrument"; CREATE TABLE IF NOT EXISTS "Instrument" ( "Symbol" TEXT NOT NULL, "IsPermitted" INTEGER NOT NULL, "IsNonDeaultSettigs" INTEGER NOT NULL);'
        if ($coins) { Invoke-SqliteQuery -DataSource $dataSource -Query $query } else {write-log -string "Found no coins data to import! Try again please." -color "Red" ; sleep 3 ; exit}
        Invoke-SQLiteBulkCopy -DataTable ($coins | Out-DataTable) -DataSource $dataSource -Table "Instrument" -NotifyAfter 1000 -Confirm:$false
        # write-log -string "Coin settings imported to $($dataSource)" -color "Green"
        write-host ""
    } else {
        write-log -string "Data could not be obtained. Waiting till next cycle..." -color "red"
    }
    betterSleep ($settings.refresh * 60) "AutoCoins $($version) (path: $($path))"
}


