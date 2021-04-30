### author:  Daisy
### discord: Daisy#2718
### site:    https://github.com/daisy613/autoCoins
### issues:  https://github.com/daisy613/autoCoins/issues
### tldr:    This Powershell script dynamically controls the coin list in WickHunter bot to blacklist\un-blacklist coins based on proximity to ATH, 1hr/24hr price change and minimum coin age.
### Changelog:
### * added geoIp info
### * added a random wait (up to one sec) into each thread to confuse the API thresholds
### * fixed log truncating
### * fixed discord rate limiting issues

$path = Split-Path $MyInvocation.MyCommand.Path

### run powershell as admin
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments -WorkingDirectory $path
    Break
}

$version = "v1.2.8"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
$host.UI.RawUI.WindowTitle = "AutoCoins $($version) - $($path)"

If (!(Get-Module -Name "PSSQLite")) {
    Install-Module "PSSQLite" -Scope CurrentUser -SkipPublisherCheck -Confirm:$false -ea SilentlyContinue
    Import-Module "PSSQLite" -DisableNameChecking -Verbose:$false | Out-Null
}
If (!(Get-Module -Name "PoshRSJob")) {
    Install-Module "PoshRSJob" -Scope CurrentUser -SkipPublisherCheck -Confirm:$false -ea SilentlyContinue
    Import-Module "PoshRSJob" -DisableNameChecking -Verbose:$false | Out-Null
}

$settings = gc "$($path)\autoCoins.json" | ConvertFrom-Json
# housekeeping
if (!("cooldownHrs" -in ($settings | gm).name)) {
    $settings | Add-Member -MemberType NoteProperty -Name "cooldownHrs" -Value 4
    $settings | ConvertTo-Json | sc "$($path)\autoCoins.json" -force
}
if (!("max4hrPercent" -in ($settings | gm).name)) {
    $settings | Add-Member -MemberType NoteProperty -Name "max4hrPercent" -Value 5
    $settings | ConvertTo-Json | sc "$($path)\autoCoins.json" -force
}
if (!($settings)) { write-log -string "Cannot find $($path)\autoCoins.json file!" -color "DarkRed"; sleep 30 ; exit }
$dataSource = "$($path)\storage.db"
$logfile = "$($path)\autoCoins.log"
$maxLogSize = 20MB
$MaxJobs = 20

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

function archiveLog () {
    param ($maxLogSize = 20MB)
    $logSize = (Get-Item -Path $logFile).Length
    if ($logSize -ge $maxLogSize) {
        $logFileObject = Get-Item -Path $logFile | select *
        $archiveFileName = '{0}\{1}_{2}{3}' -f $logFileObject.Directory,$logFileObject.BaseName,(Get-Date -Format 'yyyy-MM-dd'),$logFileObject.Extension
        Copy-Item -Path $logFile -Destination $archiveFileName
        # if (test-path "$($logFile).zip") { Remove-Item "$($logFile).zip" }
        # Compress-Archive -Path $archiveFileName -DestinationPath "$($logFile).zip"
        Remove-Item -Path $logFile
    }
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

function getGeo () {
    $uri = 'https://ipapi.co/' + @(Invoke-RestMethodCustom "http://ifconfig.me/ip" $settings.proxy $settings.proxyUser $settings.proxyPass) + '/json'
    Invoke-RestMethod $uri
}

function Invoke-RestMethodCustom () {
    Param($uri,$proxy,$proxyUser,$proxyPass)
    if ($proxy -ne "http://PROXYIP:PROXYPORT" -and $proxy -ne "" -and $proxyUser -eq "") {
        $result = Invoke-RestMethod -Uri $uri -Proxy $proxy
    } elseif ($proxy -ne "http://PROXYIP:PROXYPORT" -and $proxy -ne "" -and $proxyUser -ne "") {
        $proxCred = new-object -typename System.Management.Automation.PSCredential -argumentlist ([pscustomobject] @{
            UserName = $proxyUser;
            Password = (ConvertTo-SecureString -AsPlainText -Force -String $proxyPass)[0]
          })
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
    # Param($max1hrPercent,$max24hrPercent,$minAthPercent,$minAge)
    $symbols = getSymbols
    $Global:callsTotal++
    $coins = @()
    $quarantined = @()
    write-host "Calculating coin list ...  " -f "DarkGray" -NoNewline
    $uri = "https://fapi.binance.com/fapi/v1/ticker/24hr"
    $24HrPrices = (Invoke-RestMethodCustom $uri $settings.proxy $settings.proxyUser $settings.proxyPass) | select symbol,priceChangePercent
    $Global:callsTotal++
    $openPositions = (Invoke-SqliteQuery -DataSource $DataSource -Query "SELECT symbol FROM [Order] WHERE State = 'New'").Symbol
    $symbols = $symbols | ? { $_ -notin $settings.blacklist }
    $Global:callsTotal += $symbols.length * 3
    $objects = @()
    $scriptBlock = {
        param($symbol)
        sleep (get-random -min 0.1 -max 1)
        function Invoke-RestMethodCustom ($uri,$proxy,$proxyUser,$proxyPass) {
            if ($proxy -ne "http://PROXYIP:PROXYPORT" -and $proxy -ne "" -and $proxyUser -eq "") {
                $result = Invoke-RestMethod -Uri $uri -Proxy $proxy
            } elseif ($proxy -ne "http://PROXYIP:PROXYPORT" -and $proxy -ne "" -and $proxyUser -ne "") {
                $proxCred = new-object -typename System.Management.Automation.PSCredential -argumentlist ([pscustomobject] @{
                    UserName = $proxyUser;
                    Password = (ConvertTo-SecureString -AsPlainText -Force -String $proxyPass)[0]
                  })
                $result = Invoke-RestMethod -Uri $uri -Proxy $proxy -ProxyCredential $proxCred
            } else {
                $result = Invoke-RestMethod -Uri $uri
            }
            return $result
        }
        $settings = $Using:settings
        # calculate the 1hr price change
        if ($settings.cooldownHrs -ge 4) {
            $minCandles = $settings.cooldownHrs
        } else { $minCandles = 4 }
        $dateTime = get-date -format "yyyy-MM-dd HH:mm:ss"
        $limit = $minCandles * 60
        $uri = "https://fapi.binance.com/fapi/v1/klines?symbol=$($symbol)&interval=1m&limit=$($limit)"
        $1hrPrices = (Invoke-RestMethodCustom $uri $settings.proxy $settings.proxyUser $settings.proxyPass) | % { $_[1] }
        $1hrPercent = @()
        $i = 0
        do {
            $i++
            $end = $i * 60 - 1
            $start = $end - 59
            $1hrPercent += (($1hrPrices[$end] - $1hrPrices[$start]) * 100) / $1hrPrices[$end]
        } until ($i -eq $minCandles)
        $4hrPercentCurr = (($1hrPrices[239] - $1hrPrices[0]) * 100) / $1hrPrices[239]
        $24hrPercentCurr = ($Using:24HrPrices | ? { $_.symbol -eq $symbol}).priceChangePercent
        # calculate age
        $uri = "https://fapi.binance.com/fapi/v1/klines?symbol=$($symbol)&interval=1d&limit=1500"
        $age = (Invoke-RestMethodCustom $uri $settings.proxy $settings.proxyUser $settings.proxyPass).length
        # calculate ATH percentage
        # NOTE: the ATH calculation only shows the past 20 months due to Binance restrictions, so it's not a true ATH.
        $limit = [math]::Round((($age / 30) + 1), 0)
        $uri = "https://fapi.binance.com/fapi/v1/klines?symbol=$($symbol)&interval=1M&limit=$($limit)"
        $ath = [decimal] ((Invoke-RestMethodCustom $uri $settings.proxy $settings.proxyUser $settings.proxyPass) | % { $_[2] } | measure -Maximum).Maximum
        $athPercentCurr = (($ath - $1hrPrices[-1]) * 100 / $ath)
        $x = $settings.cooldownHrs - 1
        [PSCustomObject][object]@{
            "symbol"      = $symbol
            "perc1hr"     = $(if (($1hrPercent[0..$x] | % { [math]::Abs($_) } | measure -Maximum).Maximum -lt $settings.max1hrPercent) { "PASS" } else { "FAIL" })
            "perc1hrVal"  = $1hrPercent[0..$x] | % { [math]::Round($_,2) }
            "perc4hr"     = $(if ([math]::Abs($4hrPercentCurr) -lt $settings.max4hrPercent) { "PASS" } else { "FAIL" })
            "perc4hrVal"  = [math]::Round($4hrPercentCurr,2)
            "perc24hr"    = $(if ([math]::Abs($24hrPercentCurr) -lt $settings.max24hrPercent) { "PASS" } else { "FAIL" })
            "perc24hrVal" = [math]::Round($24hrPercentCurr,2)
            "Ath"         = $(if ($athPercentCurr -gt $settings.minAthPercent) { "PASS" } else { "FAIL" })
            "AthVal"      = [math]::Round($athPercentCurr,2)
            "Age"         = $(if ($age -gt $settings.minAge) { "PASS" } else { "FAIL" })
            "AgeVal"      = $age
            "Open"        = $(if ($symbol -notin $Using:openPositions) { "PASS" } else { "FAIL" })
            "dateTime"    = $dateTime
        }
    }
    $stopWatch = [system.diagnostics.stopwatch]::StartNew()
    $symbols | Start-RSJob -ArgumentList $_ -Throttle $MaxJobs -ScriptBlock $scriptBlock | out-null
    $PollingInterval = 1
    $CompletedThreads = 0
    $PctComplete = 0
    $CurrentJobs = @()
    $Status = Get-RSJob | Group-Object -Property State
    $TotalThreads = ($Status | Select-Object -ExpandProperty Count | Measure-Object -Sum).Sum
    while ($CompletedThreads -lt $TotalThreads) {
        $CurrentJobs = Get-RSJob
        $objects += $CurrentJobs.Where( { $PSItem.State -eq "Completed" }) | Receive-RSJob
        $CurrentJobs.Where( { $PSItem.State -eq "Completed" }) | Remove-RSJob #| Out-Null
        $Status = $CurrentJobs | Group-Object -Property State
        $CompletedThreads += $Status | Where-Object { $PSItem.Name -eq "Completed" } | Select-Object -ExpandProperty Count
        $PctComplete = ($CompletedThreads / $TotalThreads) * 100
        if ($PctComplete -gt 100) {$PctComplete = 100}
        Write-Progress -Activity "AutoCoins processing symbols..." -Status "Symbols processed: $CompletedThreads/$TotalThreads ($([math]::Round($PctComplete,0))%)" -PercentComplete $PctComplete
        Start-Sleep -Seconds $PollingInterval
    }
    $quarantined   = ($objects | ? { ($_.perc1hr -eq "FAIL" -or $_.perc24hr -eq "FAIL"  -or $_.perc4hr -eq "FAIL" -or $_.Ath -eq "FAIL" -or $_.Age -eq "FAIL") -and $_.Open -eq "PASS" }).symbol | sort
    $permittedCurr = ((Invoke-SqliteQuery -DataSource $dataSource -Query "SELECT * FROM Instrument")  | ? {$_.IsPermitted -eq 1 }).symbol | sort
    $permitted     = $symbols | ? {$_ -notin  $quarantined} | sort
    $unQuarantined = $permitted | ? {$_ -notin  $permittedCurr} | sort
    $openNotQuarantined = ($objects | ? { $_.Open -eq "FAIL" -and ($_.perc1hr -eq "FAIL" -or $_.perc24hr -eq "FAIL" -or $_.Ath -eq "FAIL" -or $_.Age -eq "FAIL") }).symbol
    $stopWatch.Stop()
    $executionTime = [math]::Round($stopWatch.Elapsed.TotalSeconds, 0)
    write-host "[ executionTime: $executionTime secs | parallel threads: $MaxJobs ]" -f darkgray
    marketSwing $objects
    $objects | select symbol,perc1hrVal,perc1hr,perc4hrVal,perc4hr,perc24hrVal,perc24hr,AthVal,Ath,AgeVal,Age,Open | ft -autosize | out-file -append $logfile -encoding ASCII
    write-log -string "Quarantined: $($quarantined -join ', ')" -color "yellow"
    $message = "**QUARANTINED**: $($quarantined -join ', ')"
    sendDiscord $settings.discord $message
    if ($unQuarantined) {
        write-log -string "Un-Quarantined: $($unQuarantined -join ', ')" -color "yellow"
        $message = "**UNQUARANTINED**: $($unQuarantined -join ', ')"
        sendDiscord $settings.discord $message
    }
    if ($openNotQuarantined) {
        write-log -string "Open Positions (could not quarantine): $($openNotQuarantined -join ', ')" -color "yellow"
        $message = "**OPEN POSITIONS - NOT QUARANTINED**: $($openNotQuarantined -join ', ')"
        sendDiscord $settings.discord $message
    }
    return $permitted
}

function marketSwing () {
    param ($objects)
    $poscoincount1 = ($objects | % {$_.perc1hrVal[0]} | ? { $_ -ge 0 }).count
    $poscoinaverage1 = ($objects | % {$_.perc1hrVal[0]} | ? { $_ -ge 0 } | measure -Average).Average
    $negcoincount1 = ($objects | % {$_.perc1hrVal[0]} | ? { $_ -lt 0 }).count
    $negcoinaverage1 = ($objects | % {$_.perc1hrVal[0]} | ? { $_ -lt 0 } | measure -Average).Average
    $posmax1 = ($objects | % {$_.perc1hrVal[0]} | ? { $_ -ge 0 } | measure -Maximum).Maximum
    $posmaxcoin1 =  ($objects | ? {$_.perc1hrVal[0] -eq $posmax1}).symbol
    $negmax1 = ($objects | % {$_.perc1hrVal[0]} | ? { $_ -lt 0 } | measure -Minimum).Minimum
    $negmaxcoin1 = ($objects | ? {$_.perc1hrVal[0] -eq $negmax1}).symbol
    $counttotal1 = $poscoincount1 + $negcoincount1
    $pospercent1 = ($poscoincount1 / $counttotal1) * 100
    $pospercent1 = [math]::Round($pospercent1, 0)
    $negpercent1 = 100 - $pospercent1
    $posave1 = [math]::Round($poscoinaverage1, 2)
    $negave1 = [math]::Round($negcoinaverage1, 2)
    $posmax1 = [math]::Round($posmax1, 2)
    $negmax1 = [math]::Round($negmax1, 2)

    $poscoincount4 = ($objects | % {$_.perc4hrVal[0]} | ? { $_ -ge 0 }).count
    $poscoinaverage4 = ($objects | % {$_.perc4hrVal[0]} | ? { $_ -ge 0 } | measure -Average).Average
    $negcoincount4 = ($objects | % {$_.perc4hrVal[0]} | ? { $_ -lt 0 }).count
    $negcoinaverage4 = ($objects | % {$_.perc4hrVal[0]} | ? { $_ -lt 0 } | measure -Average).Average
    $posmax4 = ($objects | % {$_.perc4hrVal[0]} | ? { $_ -ge 0 } | measure -Maximum).Maximum
    $posmaxcoin4 =  ($objects | ? {$_.perc4hrVal[0] -eq $posmax4}).symbol
    $negmax4 = ($objects | % {$_.perc4hrVal[0]} | ? { $_ -lt 0 } | measure -Minimum).Minimum
    $negmaxcoin4 = ($objects | ? {$_.perc4hrVal[0] -eq $negmax4}).symbol
    $counttotal4 = $poscoincount4 + $negcoincount4
    $pospercent4 = ($poscoincount4 / $counttotal4) * 100
    $pospercent4 = [math]::Round($pospercent4, 0)
    $negpercent4 = 100 - $pospercent4
    $posave4 = [math]::Round($poscoinaverage4, 2)
    $negave4 = [math]::Round($negcoinaverage4, 2)
    $posmax4 = [math]::Round($posmax4, 2)
    $negmax4 = [math]::Round($negmax4, 2)

    $poscoincount24 = ($objects.perc24hrVal | ? { $_ -ge 0 }).count
    $poscoinaverage24 = ($objects.perc24hrVal | ? { $_ -ge 0 } | measure -Average).Average
    $negcoincount24 = ($objects.perc24hrVal | ? { $_ -lt 0 }).count
    $poscoinaverage24 = ($objects.perc24hrVal | ? { $_ -lt 0 } | measure -Average).Average
    $posmax24 = ($objects.perc24hrVal | ? { $_ -ge 0 } | measure -Maximum).Maximum
    $posmaxcoin24 =  ($objects | ? {$_.perc24hrVal -eq $posmax24}).symbol
    $negmax24 = ($objects.perc24hrVal | ? { $_ -lt 0 } | measure -Minimum).Minimum
    $negmaxcoin24 = ($objects | ? {$_.perc24hrVal -eq $negmax24}).symbol
    $counttotal24 = $poscoincount24 + $negcoincount24
    $pospercent24 = ($poscoincount24 / $counttotal24) * 100
    $pospercent24 = [math]::Round($pospercent24, 0)
    $negpercent24 = 100 - $pospercent24
    $posave24 = [math]::Round($poscoinaverage24, 2)
    $negave24 = [math]::Round($negcoinaverage24, 2)
    $posmax24 = [math]::Round($posmax24, 2)
    $negmax24 = [math]::Round($negmax24, 2)
    $swing1 = $pospercent1 - $negpercent1
    if ($swing1 -lt 0) {
        $swing1 = [math]::Abs($swing1)
        $swingmood1 = "$swing1% Bearish"
    } else { $swingmood1 = "$swing1% Bullish" }
    $swing4 = $pospercent4 - $negpercent4
    if ($swing4 -lt 0) {
        $swing4 = [math]::Abs($swing4)
        $swingmood4 = "$swing4% Bearish"
    } else { $swingmood4 = "$swing4% Bullish" }
    $swing24 = $pospercent24 - $negpercent24
    if ($swing24 -lt 0) {
        $swing24 = [math]::Abs($swing24)
        $swingmood24 = "$swing24% Bearish"
    } else { $swingmood24 = "$swing24% Bullish" }
    # $longvwap24 = [math]::Round((($settings.longVwapMax - $settings.longVwapMin) * ($negpercent24 / 100)) + $settings.longVwapMin, 1)
    # $shortvwap24 = [math]::Round((($settings.shortVwapMax - $settings.shortVwapMin) * ($pospercent24 / 100)) + $settings.shortVwapMin, 1)
    # $longvwap1 = [math]::Round((($settings.longVwapMax - $settings.longVwapMin) * ($negpercent1 / 100)) + $settings.longVwapMin, 1)
    # $shortvwap1 = [math]::Round((($settings.shortVwapMax - $settings.shortVwapMin) * ($pospercent1 / 100)) + $settings.shortVwapMin, 1)
    Write-Host "`nMarketSwing 1hr - $swingmood1" -f cyan
    # Write-Host "| Recommended lVwap: $longvwap1".PadRight(10) -f "cyan" -NoNewline
    Write-Host "| $pospercent1% Long | $poscoincount1 Coins | Average $posave1% | Max $posmax1% $posmaxcoin1" -f "green"
    # Write-Host "| Recommended sVwap: $shortvwap1".PadRight(10) -f "cyan" -NoNewline
    Write-Host "| $negpercent1% Short | $negcoincount1 Coins | Average $negave1% | Max $negmax1% $negmaxcoin1" -f "magenta"
    Write-Host "MarketSwing 4hrs - $swingmood4" -f cyan
    # Write-Host "| vwap $longvwap4".PadRight(10) -f "cyan" -NoNewline
    Write-Host "| $pospercent4% Long | $poscoincount4 Coins | Average $posave4% | Max $posmax4% $posmaxcoin4" -f "green"
    # Write-Host "| vwap $shortvwap4".PadRight(10) -f "cyan" -NoNewline
    Write-Host "| $negpercent4% Short | $negcoincount4 Coins | Average $negave4% | Max $negmax4% $negmaxcoin4" -f "magenta"
    Write-Host "MarketSwing 24hrs - $swingmood24" -f cyan
    # Write-Host "| vwap $longvwap24".PadRight(10) -f "cyan" -NoNewline
    Write-Host "| $pospercent24% Long | $poscoincount24 Coins | Average $posave24% | Max $posmax24% $posmaxcoin24" -f "green"
    # Write-Host "| vwap $shortvwap24".PadRight(10) -f "cyan" -NoNewline
    Write-Host "| $negpercent24% Short | $negcoincount24 Coins | Average $negave24% | Max $negmax24% $negmaxcoin24`n" -f "magenta"
    $message = "**MarketSwing - Last 1hr** - $swingmood1`n$pospercent1% Long | $poscoincount1 Coins | Ave $posave1% | Max $posmax1% $posmaxcoin1`n" + "$negpercent1% Short | $negcoincount1 Coins | Ave $negave1% | Max $negmax1% $negmaxcoin1 `n**MarketSwing - Last 4hrs** - $swingmood4`n$pospercent4% Long | $poscoincount4 Coins | Ave $posave4% | Max $posmax4% $posmaxcoin4`n" + "$negpercent4% Short | $negcoincount4 Coins | Ave $negave4% | Max $negmax4% $negmaxcoin4 `n**MarketSwing - Last 24hrs** - $swingmood24`n$pospercent24% Long | $poscoincount24 Coins | Ave $posave24% | Max $posmax24% $posmaxcoin24`n" + "$negpercent24% Short | $negcoincount24 Coins | Ave $negave24% | Max $negmax24% $negmaxcoin24"
    sendDiscord $settings.discord $message
    # $message = "**MarketSwing - Last 4hrs** - $swingmood4`n$pospercent4% Long | $poscoincount4 Coins | Ave $posave4% | Max $posmax4% $posmaxcoin4`n" + "$negpercent4% Short | $negcoincount4 Coins | Ave $negave4% | Max $negmax4% $negmaxcoin4"
    # sendDiscord $settings.discord $message
    # $message = "**MarketSwing - Last 24hrs** - $swingmood24`n$pospercent24% Long | $poscoincount24 Coins | Ave $posave24% | Max $posmax24% $posmaxcoin24`n" + "$negpercent24% Short | $negcoincount24 Coins | Ave $negave24% | Max $negmax24% $negmaxcoin24"
    # sendDiscord $settings.discord $message
}

write-host "`n`n`n`n`n`n`n`n`n`n"

$stopWatchMain = [system.diagnostics.stopwatch]::StartNew()
checkLatest
$geoInfo = getGeo
$Global:callsTotal = $null
while ($true) {
    # $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    archiveLog $maxLogSize
    $settings = gc "$($path)\autoCoins.json" | ConvertFrom-Json
    if ($settings.proxy -ne "http://PROXYIP:PROXYPORT" -and $settings.proxy -ne "") {
        $geoInfo = getGeo
        write-log -string "Using proxy [ $($settings.proxy) | geoIp: $($geoInfo.ip)/$($geoInfo.country_name) ]" -color "DarkGray"
    }
    $coinList = getInfo
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
    $executionTimeTotal = $stopWatchMain.Elapsed.TotalSeconds
    write-log -string "Avg API Calls/min: $([math]::Round($Global:callsTotal/($executionTimeTotal/60),0)) | running time: $([math]::Round($executionTimeTotal/60,1)) mins" -color "DarkGray"
    betterSleep ($settings.refresh * 60) "AutoCoins: $($version) - by: Daisy - path: $($path) - geoIp: $($geoinfo.ip)/$($geoinfo.country_name)"
}

