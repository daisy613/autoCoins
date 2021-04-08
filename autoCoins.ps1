### author:  Daisy
### discord: Daisy#2718
### site:    https://github.com/daisy613/autoCoins
### issues:  https://github.com/daisy613/autoCoins/issues
### tldr:    This script dynamically controls the coin list in WickHunter bot to blacklist\un-blacklist coins based on proximity to ATH, 1hr price change and minimum coin age.
### Changelog:
### * added script version to the progress bar
### * added proxy support (please delete your old json settings file and use the new one)

$path = Split-Path $MyInvocation.MyCommand.Path

### run powershell as admin
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments -WorkingDirectory $path
    Break
}

$version = "v1.0.1"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

$settings = gc "$($path)\autoCoins.json" | ConvertFrom-Json
if (!($settings)) { write-host "Cannot find $($path)\autoCoins.json file!" -foregroundcolor "DarkRed" -backgroundcolor "yellow"; sleep 30 ; exit }

### blacklist
$blackList = $settings.blacklist
### cutoff 1hr percentage change, in %
$min1hPercent = $settings.max1hrPercent
### cutoff ATH percentage, in %
$maxAthPercent = $settings.minAthPercent
### cutoff coin age, in days
$minAge = $settings.minAge
### data refresh interval, in mins
$refresh = $settings.refresh
### if proxy is specified
$proxy = $settings.proxy

######################################################################################################

function checkLatest () {
    $repo = "daisy613/autoCoins"
    $releases = "https://api.github.com/repos/$repo/releases"
    $latestTag = [array](Invoke-WebRequest $releases | ConvertFrom-Json)[0].tag_name
    $youngerVer = ($version, $latestTag | Sort-Object)[-1]
    if ($latestTag -and $version -ne $youngerVer) {
        write-host "Your version of $($repo) [$($version)] is outdated. Newer version [$($latestTag)] is available: https://github.com/$($repo)/releases/tag/$($latestTag)" -b "Red"
    }
}

If (-not (Get-Module -Name "PSSQLite")) {
    Import-Module "PSSQLite" -DisableNameChecking -Verbose:$false | Out-Null
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

function getSymbols () {
    $request = 'Invoke-RestMethod -Uri "https://fapi.binance.com/fapi/v1/exchangeInfo"' + $proxyString
    $symbols = ((Invoke-Expression $request).symbols).symbol | Sort-Object
    return $symbols
}

# https://binance-docs.github.io/apidocs/futures/en/#kline-candlestick-data
function getInfo () {
    Param($min1hPercent,$maxAthPercent,$minAge)
    $symbols = getSymbols
    $coins = @()
    $quarantine = @()
    $count = 0
    foreach ($symbol in $symbols) {
        $count++
        $percentDone = $count / $symbols.length * 100
        Write-Progress -Activity "Calculating ..." -Status "Processed $($count)/$($symbols.length) symbols..." -PercentComplete $percentDone
        # calculate the 1hr price change
        $request = 'Invoke-RestMethod -Uri "https://fapi.binance.com/fapi/v1/klines?symbol=$($symbol)&interval=1m&limit=60"' + $proxyString
        $1hrPrices = (Invoke-Expression $request) | % { $_[1] }
        $1hrPercentCurr = [math]::Abs((($1hrPrices[-1] - $1hrPrices[0]) * 100) / $1hrPrices[-1])
        #calculate ATH percentage
        $request = 'Invoke-RestMethod -Uri "https://fapi.binance.com/fapi/v1/klines?symbol=$($symbol)&interval=1M&limit=500"' + $proxyString
        $ath = [decimal] ((Invoke-Expression $request) | % { $_[2] } | measure -Maximum).Maximum
        $athPercentCurr = (($ath - $1hrPrices[-1]) * 100 / $ath)
        # calculate age
        $request = 'Invoke-RestMethod -Uri "https://fapi.binance.com/fapi/v1/klines?limit=1500&symbol=$symbol&interval=1d"' + $proxyString
        $age = (Invoke-Expression $request).length
        if ($1hrPercentCurr -lt $min1hPercent -and $athPercentCurr -gt $maxAthPercent -and $age -gt $minAge) {
            $coins += $symbol
        }
        else {
            $quarantine += $symbol
        }
    }
    write-host "[$date] Quarantined coins: $($quarantine -join ', ')" -f "yellow"
    return $coins
}

write-host "`n`n`n`n`n`n`n`n`n`n"
checkLatest

while ($true) {
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $dataSource = "$path\storage.db"
    if ($proxy -ne "http://PROXYIP:PROXYPORT" -and $proxy -ne "") {
        $proxyString = " -proxy $($proxy)"
        write-host "[$date] Using proxy $($settings.proxy)" -f "Cyan"
    } else { $proxyString = "" }
    write-host "[$date] Calculating coin list ..." -f "Yellow"
    $openPositions = (Invoke-SqliteQuery -DataSource $DataSource -Query "SELECT symbol FROM [Order] WHERE State = 'New'").Symbol
    $coinList = getInfo $min1hPercent $maxAthPercent $minAge | ? { $_ -notin $blackList }
    if ($coinList) {
        $coinList = $coinList + $openPositions | sort -uniq
        # write-host "Backing up your current WH database..." -f "Green"
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
        if ($coins) { Invoke-SqliteQuery -DataSource $dataSource -Query $query } else {write-host "Found no coins data to import! Try again please." -f "Red" ; sleep 3 ; exit}
        Invoke-SQLiteBulkCopy -DataTable ($coins | Out-DataTable) -DataSource $dataSource -Table "Instrument" -NotifyAfter 1000 -Confirm:$false
        write-host "Coin settings imported to $($dataSource)" -f "Green"
    }
    else {
        write-host "[$date] Data could not be obtained. Waiting till next cycle..." -f "red"
    }
    betterSleep ($refresh * 60) "AutoCoins $($version) (path: $($path))"
}
