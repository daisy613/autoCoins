# :blossom: AutoCoins
(from [WH scripts collection](https://github.com/daisy613/wickHunter-scripts))

![](https://i.imgur.com/irVC0PS.png)
![](https://i.imgur.com/4VUpzYf.png)

## What it does:
- This Powershell script allows you to avoid most pumps/dumps by dynamically controlling the coin-list in WickHunter bot to blacklist\un-blacklist coins based on the following conditions:
  - combination of 1hr, 4hr and 24hr price percentage changes.
  - proximity to All Time High.
  - minimum coin age.
- The script **overrides the existing coin list in WickHunter**, no need to pause the bot.
- The script **does not** blacklist coins that are in open positions.

## Instructions:
- Drop the script file and the json settings file into the same folder with your bot. **Make sure the folder is not located on your desktop but is a dedicated folder elsewhere on your drive.**
- Make sure you have WickHunter bot version **v0.6.2** or higher.
- Define the following in autoCoins.json file
  - **max1hrPercent**: maximum 1hr price change percentage (default = 5).
  - **max4hrPercent**: maximum 4hr price change percentage (default = 5).
  - **max24hrPercent**: maximum 24hr price change percentage (default = 10).
  - **cooldownHrs**: the number of 1hr candles into the past to check for the price changes. Example: if the number is 4 (default), the bot will quarantine coins that had a 1hr price change more than defined in _max1hrPercent_ within the past X _cooldownHrs_ (default = 4). Note: cooldown only applies to 1hr changes, not to ATH or 24hr price changes.
  - **minAthPercent**: minimum proximity to ATH in percent (default = 5). Note: due to Binance limitations, the ATH is only pulled from the last 20 months, so it's not a true All Time High, but ATH-ish.
  - **minAge**: minimum coin age in days (default = 14).
  - **refresh**: the period in minutes of how often to check (recommended minimum 15 mins due to possibility of over-running your API limit) (default = 15).
  - **discord**: (optional) your discord webhook.
  - **proxy**: (optional) IP proxy and port to use (example "http://25.12.124.35:2763"). Leave blank if no proxy used (""). Get proxy IPs [here](https://www.webshare.io/?referral_code=wn3nlqpeqog7). Note: you don't need to use ProxyCap, as you would for the bot itself. All you have to do is get one of the IPs from the list WebShare site gives you when you sign up.
  - **proxyUser**: (optional) proxy user.
  - **proxyPass**: (optional) proxy password.
  - **blacklist**: permanently blacklisted coins.
- Double-click on the script or run it in Powershell console.
- Submit any issues or enhancement ideas on the [Issues](https://github.com/daisy613/autoCoins/issues) page. I cannot monitor the main discord chat all the time so I can't respond to all questions/issues there.

## Troubleshooting:
- If you get the error "Invoke-Sqlite query : Exception calling "Fill" with "1" arguments..." - Make sure the folder is not located on your desktop but is a dedicated folder elsewhere on your drive. You can also right-click on the script file and uncheck the Block check-mark.
- If you get the error saying that the script is not digitally signed, run the following command at the Administrative Powershell console:
  - Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
- If you are not sure why a certain coin was quarantined or not, please check the autoCoins.log file for the detailed reasons for each coin.

## Donations/Tips:
- USDT (TRC20): `TWhjv6ita4Y1i2xevTjxgB6g92yZLpkTwv`
- BTC: `13nsGbe7A7K1SR2KpJHRPH9eArKf823T9o`
