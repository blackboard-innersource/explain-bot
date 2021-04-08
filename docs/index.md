
# Explain Bot

**Explain Bot** is a slackbot, written in Python and deployed to AWS with CDK. The purpose of this bot is to help users learn about acronyms in use at Blackboard, with a focus around SAFe terms. That said, it is not limited in anyway. 

## Getting started

In order to configure and run this application, you will need to have a slack application configured. The easiest way to get started is to login to https://blackboard-sandbox.slack.com with your ADFS credentials, select _Customize Blackboard-Sandbox_ from the space menu, and then click _Configure Apps_ in the left-hand navigation. Once you do this, you will see a link in the top navigation to the right called _Build_. 

On the subsequent page, simply click the _Create New App_ button. Give your app a name and then in the _Development Slack Workspace_ dropdown, select Blackboard-Sandbox. Then click _Create App_.

On the page that loads when you create your application, you will see a form with _App Credentials_. Click _Show_ for your Signing Secret and copy that value to the clipboard.

In this project, copy ConfigTempalte.py to Config.py, and paste your signing secret as the value for "SLACK_SIGNING_SECRET". The application will use this value to validate incoming requests from Slack.

Next, click _Slash Commands_ in the left-hand navigation and click _Create New Command_. Enter a name for your command **WITH** the slash. I called it `/explain` but the app doesn't care what you call it. In the URL field, put a dummy URL. We will fill this in after we deploy the app. Give it a short description, which is required, and then a usage hint if you like, the click _Save_.

Now, from the left-hand menu, click _Interactivity & Shortcuts_. Click the toggle to turn on Interactivity and add a dummy URL to _Request URL_ and click _Save Changes_. We will fill this in once the application is deployed to AWS.

To continue further, we will need to install the application to the Slack workspace. In the left-hand navigation click _Install App_ and the click _Request to Install_. This will send a request to DIRE. You should also open a DIRE ticket to ensure they are aware of the request. 

Once the app is installed in the Blackboard-Sandbox workspace, the app will provide you the last piece of information we require for deployment. Back in the place where you registered and configured you application, there is a left-hand navigation item for _OAuth & Permissions_. Click this link and copy the _Bot User OAuth Token_ to your clipboard. Paste this token in your Config.py as the value for the "OAUTH_TOKEN" key. 

Lastly, in the Config.py file, add the Slack usernames to the "UPDATES" comma-delimited string that you wish to be able to add new definitions. Save Config.py. We are almost there.

Next, activate the virtual environment. If you are on Windows, execute `./source.bat` from the commandline in the project directory. If you are on Mac, execute `. .env/bin/activate` in the terminal inside the project directory. 

Now run `pip install --upgrade -r requirements.txt`.

## Deploy

To deploy the script, you will need a few things. First, you will need [CDK installed](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html). You will also need your environment set up with AWS credentials with appropriate permissions to create assets in AWS. I built and tested on Windows 10 using saml2aws.exe and then a profile based on those credentials with elevated priviliges. My elevated profile is called OKTAPOWERUSER. I will use this in the commands below. Replace with your profile name.

1. Boostrap your project: `cdk --profile OKTAPOWERUSER bootstrap`
2. Then deploy: `cdk --profile OKTAPOWERUSER deploy` and follow the onscreen instructions.

That's it, you are deployed.

We have created a number of things:

* An Application, that contains...
* API Gateway
* Two Lambdas
* DynamoDb Table
* Custom Resources that populated that table with the base data
* All the roles and links required to tie the stack together.

## Configure your application and test

Now that the application is running in AWS, the last step is to add the real URLs to the Slack App and then test. To get that value, we need to login to the AWS Management Console, with enough priviliges to view the application. Navigate to [API Gateway](https://console.aws.amazon.com/apigateway/main/apis) and select _ExplainSlackBotApi_. Right click the Invoke URL and copy the link address. Now navigate back to your [Slack Application](https://api.slack.com/apps). Click into your application, and on the subsequent screen, click _Interactivity & Shortcuts_. In the _Request URL_ text box, paste the invoke URL and append `add_meaning`, so you should end up with `https://<api id>.execute-api.us-east-1.amazonaws.com/add_meaning`. Click _Save Changes_.

Now click _Slash Commands_ in the left-hand navigation and then click the pencil icon next to the slash command you created. Paste the Invoke URL into the _Request URL_ text box. It should look like `https://<api id>.execute-api.us-east-1.amazonaws.com/`. Click _Save_.

Now simply login to Blackboard-Sandbox.slack.com with your AFDS credentials, and type `/explain lace` and press ENTER. Of course if you called it something other than `/explain`, use your command. It should return the definition. Now, assuming you added yourself as an "UPDATER", type `explain CDK Cloud Development Kit` and press ENTER. This will load a modal that you can accept as is or edit and then click _Submit_. You have now defined a new acronym available to all. 

## How to contribute

This is 100% MVP level. There are a number of enhancements, which I will add as issues to this repo. In addition, I wrote this to learn CDK, so feel free to help improve the CDK implementation. I only ask that you create an issue and document what you are changing and why, so I, as well as anyone else that comes along, can learn why you have made that change.

