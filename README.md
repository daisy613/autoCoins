# :blossom: AutoCoins
(from [WH scripts collection](https://github.com/daisy613/wickHunter-scripts))

![](https://i.imgur.com/bHQ9uC5.png)

## What it does:
- This Powershell script dynamically controls the coin list in WickHunter bot to blacklist\un-blacklist coins based on the following conditions:
  - 1hr price percentage change.
  - proximity to All Time High.
  - minimum coin age.
- The script overrides the existing coin list in WickHunter, no need to pause the bot.
- The script **does not** blacklist coins that are in open positions.

## Instructions:
- Drop the script file and the json settings file into the same folder with your bot.
- Define the following in autoCoins.json file
  - **max1hrPercent**: maximum 1hr price change percentage.
  - **minAthPercent**: minimum proximity to ATH in percent.
  - **minAge**: minimum coin age in days.
  - **refresh**: the period in minutes of how often to check (recommended minimum 15 mins due to possibility of over-running your API limit).
  - **proxy**: (optional) IP proxy and port to use (example "http://25.12.124.35:2763"). Leave blank if no proxy used (""). Get proxy IPs [here](https://www.webshare.io/?referral_code=wn3nlqpeqog7).
  - **blacklist**: permanently blacklisted coins.
- Submit any issues or enhancement ideas on the [Issues](https://github.com/daisy613/autoCoins/issues) page.

## Tips:
- USDT (TRC20): TNuwZebdZmoDxrJRxUbyqzG48H4KRDR7wB
- BTC: 1PV97ppRdWeXw4TBXddAMNmwnknU1m37t5
- USDT/ETH (ERC20): 0x56b2239c6bde5dc1d155b98867e839ac502f01ad
