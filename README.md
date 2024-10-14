# email-skeeter

This is an AWS Lambda Function that will take an SNS notification from Simple Email Service, parse out relevant data (in my case, Sound Transit email alerts), and post them to BlueSky.

This is presented as-is with no implied warranty that it is fit for any purpose, etc etc.


# Setup

## Route 53

1. Buy a domain. This is like $15/year for a dot-com.
2. Go to Hosted Zones, and click on your domain.
3. Click on Create Record. Create an MX type record. You will be using this in SES, later.

## Simple Email Service

First, attach your domain to SES.

1. Go to Identities, click on Create Identity, and create a Domain identity matching the MX Record you created above. Go ahead and click on Easy DKIM, since it's route 53, AWS will configure the records for you. 

Next, we're going to invent an address to receive email alerts. 
1. Go to Email Receiving and create a new Rule Set. 
2. Add a new rule. Add a Receipt Condition matching your invented email address. Add an Action to Publish to an Amazon SNS topic. (Amazon should create a new topic and give it the appropriate permissions.)
3. Create a 2nd rule. This one should have no Conditions (match all), and should have a Return bounce response action.
4. Make sure your 1st rule is positioned above the 2nd in your rule set.


## Lambda

We're going to create a Lambda Function and a Layer to hold all of our python dependencies.

__Layer__

It's somewhat complicated to get the atproto library working if your development environment doesn't match the lambda environment; python is SUPPOSED to be run-anywhere, but in practice, it's going to have the wrong "pydantic_core" because your wheel is wrong for the Lambda runtime.

To resolve this, we're going to use virtualenv to package the requirements. The below workflow is for linux/mac machines.

1. Locally, install python3.12 and virtualenv.
2. Run `python3.12 -m venv venv`
3. Run `source venv/bin/activate`
4. Run `pip install atproto --platform manylinux2014_x86_64 --only-binary=:all: --target python`
5. Run `zip -r atproto.zip python`
6. Go to AWS Lambda and open Layers.
7. Create a new Layer by uploading your `atproto.zip` file. Mark it as compatible with x86_64 and the Python 3.12 runtime.

__Function__

1. Choose Python 3.12 as the runtime, x86_64 as the Architecture.
2. Go to General Configuration and boost the memory up to 512 MB
3. Go to Triggers, and add a trigger pointing to the SNS Topic we created in the SES section. (Amazon should automatically add any permissions required.)
4. Go to Environment Variables and add anything that's required.
5. Add the Layer that we created above
6. Paste `lambda_function.py` into the Code Source Editor, and hit the little "Cloud With Up Arrow" button to Deploy Function Code.

