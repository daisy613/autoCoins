### author:  Daisy
### discord: Daisy#2718
### site:    https://github.com/daisy613/autoCoins
### issues:  https://github.com/daisy613/autoCoins/issues
### tldr:    This Powershell script dynamically controls the coin list in WickHunter bot to blacklist\un-blacklist coins based on proximity to ATH, 1hr price change and minimum coin age.
### Changelog:
### * added 24hr price change to the criteria
### * added ability to specify proxy credentials
### * added display of coins that were unquarantined
### * added discord alert for quarantined coins
### * fixed PSSQLLite install issue
### * fixed TLS issues

$path = Split-Path $MyInvocation.MyCommand.Path

### run powershell as admin
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments -WorkingDirectory $path
    Break
}

$version = "v1.1.0"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
$host.UI.RawUI.WindowTitle = "AutoCoins $($version) - $($path)"

If (-not (Get-Module -Name "PSSQLite")) {
    Install-Module "PSSQLite" -Scope CurrentUser
    Import-Module "PSSQLite" -DisableNameChecking -Verbose:$false | Out-Null
}

$settings = gc "$($path)\autoCoins.json" | ConvertFrom-Json
if (!($settings)) { write-log -string "Cannot find $($path)\autoCoins.json file!" -color "DarkRed"; sleep 30 ; exit }
$dataSource = "$($path)\storage.db"
$logfile = "$($path)\autoCoins.log"

### blacklist
$blackList = $settings.blacklist
### cutoff 1hr percentage change, in %
$max1hr24hrPercent = $settings.max1hr24hrPercent
### cutoff ATH percentage, in %
$maxAthPercent = $settings.minAthPercent
### cutoff coin age, in days
$minAge = $settings.minAge
### data refresh interval, in mins
$refresh = $settings.refresh
### discord webhook
$discord = $settings.discord
### if proxy is specified
$proxy = $settings.proxy
$proxyUser = $settings.proxyUser
$proxyPass = $settings.proxyPass

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
        $proxyCred = new-object -typename System.Management.Automation.PSCredential -argumentlist ($proxyUser, $proxyPassSec)
        $result = Invoke-RestMethod -Uri $uri -Proxy $proxy -ProxyCredential $proxyCred
    } else {
        $result = Invoke-RestMethod -Uri $uri
    }
    return $result
}

function getSymbols () {
    $uri = "https://fapi.binance.com/fapi/v1/exchangeInfo"
    $symbols = ((Invoke-RestMethodCustom $uri $proxy $proxyUser $proxyPass).symbols).symbol | Sort-Object
    return $symbols
}

# https://binance-docs.github.io/apidocs/futures/en/#kline-candlestick-data
# https://binance-docs.github.io/apidocs/futures/en/#24hr-ticker-price-change-statistics
function getInfo () {
    Param($max1hr24hrPercent,$maxAthPercent,$minAge)
    $symbols = getSymbols
    $coins = @()
    $quarantined = @()
    $count = 0
    $uri = "https://fapi.binance.com/fapi/v1/ticker/24hr"
    $24HrPrices = (Invoke-RestMethodCustom $uri $proxy $proxyUser $proxyPass) | select symbol,@{ Name = 'priceChangePercent';  Expression = {[math]::Abs($_.priceChangePercent)}}
    $openPositions = (Invoke-SqliteQuery -DataSource $DataSource -Query "SELECT symbol FROM [Order] WHERE State = 'New'").Symbol
    $symbols = $symbols | ? { $_ -notin $blackList }
    foreach ($symbol in $symbols) {
        $count++
        $percentDone = $count / $symbols.length * 100
        Write-Progress -Activity "Calculating ..." -Status "Processed $($count)/$($symbols.length) symbols..." -PercentComplete $percentDone
        # calculate the 1hr price change
        $uri = "https://fapi.binance.com/fapi/v1/klines?symbol=$($symbol)&interval=1m&limit=60"
        $1hrPrices = (Invoke-RestMethodCustom $uri $proxy $proxyUser $proxyPass) | % { $_[1] }
        $1hrPercentCurr = [math]::Abs((($1hrPrices[-1] - $1hrPrices[0]) * 100) / $1hrPrices[-1])
        $24HrPricesCurr = ($24HrPrices | ? { $_.symbol -eq $symbol}).priceChangePercent
        #calculate ATH percentage
        $uri = "https://fapi.binance.com/fapi/v1/klines?symbol=$($symbol)&interval=1M&limit=500"
        $ath = [decimal] ((Invoke-RestMethodCustom $uri $proxy $proxyUser $proxyPass) | % { $_[2] } | measure -Maximum).Maximum
        $athPercentCurr = (($ath - $1hrPrices[-1]) * 100 / $ath)
        # calculate age
        $uri = "https://fapi.binance.com/fapi/v1/klines?limit=1500&symbol=$($symbol)&interval=1d"
        $age = (Invoke-RestMethodCustom $uri $proxy $proxyUser $proxyPass).length
        if ($1hrPercentCurr -lt $max1hr24hrPercent -and $1hrPercentCurr -lt $24HrPricesCurr -and $athPercentCurr -gt $maxAthPercent -and $age -gt $minAge -or $symbol -in $openPositions) {
            $coins += $symbol
        }
        else {
            $quarantined += $symbol
        }
    }
    write-log -string "[$date] Quarantined: $($quarantined -join ', ')" -color "yellow"
    $message = "**QUARANTINED**: $($quarantined -join ', ')"
    sendDiscord $discord $message
    $coinsCurr = ((Invoke-SqliteQuery -DataSource $dataSource -Query "SELECT * FROM Instrument")  | ? {$_.IsPermitted -eq 1 }).symbol | sort
    write-log -string "[$date] Un-Quarantined: $($unQuarantined -join ', ')" -color "yellow"
    $unQuarantined = $coins | ? {$_ -notin  $coinsCurr} | sort
    $message = "**UNQUARANTINED**: $($unQuarantined -join ', ')"
    sendDiscord $discord $message
    return $coins
}

write-host "`n`n`n`n`n`n`n`n`n`n"
checkLatest

while ($true) {
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if ($proxy -ne "http://PROXYIP:PROXYPORT" -and $proxy -ne "") {
        write-log -string "[$date] Using proxy $($settings.proxy)" -color "Cyan"
    }
    write-log -string "[$date] Calculating coin list ..." -color "Yellow"
    $coinList = getInfo $max1hr24hrPercent $maxAthPercent $minAge
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
        write-log -string "Coin settings imported to $($dataSource)" -color "Green"
    }
    else {
        write-log -string "[$date] Data could not be obtained. Waiting till next cycle..." -color "red"
    }
    betterSleep ($refresh * 60) "AutoCoins $($version) (path: $($path))"
}


