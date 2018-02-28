# Installing the Slack App
Unfortunately, since LimaCharlie is designed as on-premise software, it's not possible to have a public pre-defined OAuth callback for a simple deployment Slack App. But this doesn't mean it's not possible. LC just needs the App OAuth token and the Bot OAuth token.

## Create the App
First thing, login to your Slack community and go to https://api.slack.com/apps to create the LC app for your community. Click "Create new app" and name it whatever you want ("LimaCharlie" seems like a good name) and select your community.

In the next page, you can customize the display information for the app, go wild.

## Setup Privileges
The next step is to give the LC app the privileges it requires. Click "Add features and functionality", then click on "Bots". There, click "Add a bot" and set the default user name of the bot, we recommend "@lc_actual", but feel free. "Always show my bot as online" isn't required.

Now go back to "Add features and functionality" and click on "Permissions". Add the following permissions:
* channels:write (Modify your public channels, this is used to materialize investigations into channels.)
* chat:write:bot (Send messages as LimaCharlie, this is used for issuing commands with the bot.)

Then at the tom of the page, click "Install App to Team".

## Copy the Tokens
At this point, you should see an "OAuth Access Token" and a "Bot User OAuth Access Token". Copy those to the Profile page of the LimaCharlie web ui in the Slack App section.

Give it a few minutes to update, the Slack Actor in the LimaCharlie backend updates credentials every few minutes. Once it updates, you should see the Slack bot log in to your community. To see possible commands, ask it "help".