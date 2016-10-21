# IAM-BASH

## Owner
Team owning this repository: [That's Classified](https://github.com/orgs/AutoScout24/teams/that-s-classified)

## Overview of the IAM-BASH tools

The iam-bash tools are a set of sripts and files which assist devs in accessing EC2 Hosts in our AWS environments. The main two tools are:
* `as24-aws-assume.sh` - used for managing AWS security tokens - historically called by an alias `aws_assume`
* `ssh-access.sh` - used for uploading user public keys to the AWS environments - enables public key login to EC2 instances
* `as24-aws-accounts.txt` - a file providing mappings between AWS Account IDs and AS24 environment names
* `aws_assume_completion.sh` - provides bash completion for `aws_assume`

The as24-aws-assume.sh script provides AWS IAM cross-account role assumption, MFA authentication and periodic access key rotation for the **Bash shell**. The script generates and caches AWS security session tokens, so that you don't have to enter the MFA token every time a role is assumed.

The ssh-access.sh script is used to make your local public ssh key available to hosts in our AWS environments. Once there, it is referenced by all EC2 hosts and Bastion hosts to validate ssh logins.

Using these scripts will require to have setup a AWS access key profile (described directly below).

The scripts are not heavily tested, but should be MacOS and Linux compatible, and should work in different shells. If you have any issues, please submit to this repository.

## Setup an AWS Access Key Profile

Use the following steps to setup your AWS Access Key Profile:

Get an AWS Access Key file by following these steps:
* Please ensure that you're not currently logged in and assuming another role. If that's the case, kindly log out and log back in
* Log in to AWS with your IAM account
* Select the "username@as24iam" menu at the top right
* Select "Security credentials" from the menu
* Select "Users" from the left-hand panel
* Filter on your username
* Click on your username in the filtered list
* Select the "Security Credentials" tab
* Delete any existing Access keys
* Create a new Access key and download a CSV file
* Open the CSV file with a text editor and keep this information ready for the next step

* After downloading your Access key file, and with the file contents visible, run the following command:
```bash
aws configure --profile as24iam
```
* Enter the "AWS Access Key Id" and "AWS Secret Access Key" when prompted. Use "eu-west-1" as the "Default region name". Press return for the last option, "Default output format", as it doesn't need to be set.

You should now have a standard AWS Access Key Profile, stored in the `~/.aws` configuration directory. By using this profile functionality, one can avoid issues that might come up when using other accounts and profiles.

## Setting up aws_assume

Use the following steps to setup the as24-aws-assume.sh script.
* Clone this repository to a local directory on your machine.
* Add the following to your shell profile config - eg `~/.bash_profile`:

```bash
alias aws_assume='source /path/to/as24-aws-assume.sh'
```

* If you are using bash, including the following command in your profile will provide **Bash Completion** for the `aws_assume` command:

```bash
source /path/to/aws_assume_completion.sh
```

* Reload your profile by using the following command:

```bash
source ~/.bash_profile
```

Please note:
* If you still have the old `iam-bash.sh` script sourced in your profile, please remove this!
* If running the command `set | grep aws_` returns anything, then you have the old iam-bash.sh settings still active and sourced.


## Usage of aws_assume

* Running the Script without any parameters will show you the current role that you are working with:

```bash
aws_assume   # or
source as24-aws-assume.sh
```

* Additional configuration parameters are available in the script's help:
```bash
aws_assume --help
```

* Test your set up with the following:
```bash
aws_assume as24dev ReadOnlyAccess
aws ec2 describe-availability-zones --region eu-west-1
```
* This should return you a list of instances in the eu-west dev account

* Return to IAM account (where your user lives) with the following:

```bash
aws_assume --unassume
```

* Tip: assuming a role will store temporary session tokens for accessing the AWS accounts in your AWS credential profile. This profile can be used as long as the session token is valid by adding `--profile "profile name"` to your `aws` command. For example:

```bash
aws s3 ls --profile "as24dev ReadOnlyAccess"
```

* This trick will avoid you having to switch between the roles in order to issue commands using a specific role.
* It is not necessary to clear the stored tokens as they only have a limited life. If you do want to clear these tokens, however, ensure that you retain the `[as24iam]` profile (the one you set up above, to be able to use this script).

Please Note:
* the current as24-aws-assume.sh script will determine the username directly from the AWS access key in the ~/.aws profile. Therefore, it is longer an issue if your AWS account username and your Computer username don't match (this was an issue in previous versions of the script).

## Using the ssh-access.sh Script to upload your Public SSH Key 

In order to keep security on the instances and in the environments tight, you cannot directly access a EC2 microservice instance. The ssh-access.sh script will upload your public rsa SSH key, enabling you to login to hosts in the various AS24 AWS environments. There is a "Bastion Host" in each environment that you have to login to first, before accessing any further ES2 instances. 

**IMPORTANT:** Before you can upload your key, make sure you have valid aws security tokens for your user by first executing the `aws_assume` command (see description above).

In order to upload your publich ssh key, run the ssh-access.sh script with the following syntax:

```bash
ssh-access.sh [SERVICE NAME] [ACCOUNT NAME] [AWS REGION] [SSH PUBLIC KEY FILE] [USERNAME]
```

For example:
```bash
aws_assume as24dev ReadOnlyAccess
./ssh-access.sh vendor-contact-data as24dev
```

If the command was successful, you should see something like the following lines:
```
using default key at ~/.ssh/id_rsa.pub
upload: .ssh/id_rsa.pub to s3://as24-ssh-access-eu-west-1/037251718545/bastion-host/username
upload: .ssh/id_rsa.pub to s3://as24-ssh-access-eu-west-1/037251718545/vendor-contact-data/username
```

Please note:
* The last 3 command parameters- AWS REGION, SSH PUBLIC KEY FILE and USERNAME- are optional.
* Your default public rsa key will be used with the aws username registered with your AWS Access Key profile.
* This uploaded public ssh key will be deleted after 1 day and is only valid for the service name, account and region you specify.
 
Optional:
* if you wish to setup an alias, similar to the aws_assume alias above, add the following to your shell profile config - eg `~/.bash_profile`:

```bash
alias aws_ssh_access='/path/to/ssh-access.sh'
```
* It is useful to activate the SSH-Agent in your shell, to save you from being asked at every login, for your SSH Key password. Add the following to your shell profile:
```bash
eval $(ssh-agent)
ssh-add
```

Please see [Confluence](https://confluence.as24.local/display/TechnologyChange/Connect+to+an+EC2+instance+via+Bastion+host) for further details on logging in to the Bastion Hosts.

## Troubleshooting/Frequently-Asked-Questions

* As your very first troubleshooting step, please reset everything with the following commands
```bash
aws_assume --reset
aws_assume -u
```
  * This is a known fix for the following errors on the shell...
```
A client error (AccessDenied) occurred when calling the GetSessionToken operation: MultiFactorAuthentication failed with invalid MFA one time pass code.
```
```
A client error (InvalidClientTokenId) occurred when calling the ListAccessKeys operation: The security token included in the request is invalid.
```

* Please always make sure you have the latest version of the awscli installed on your system.
If you installed awscli with pip, please use:

```bash
sudo pip install awscli --upgrade
```
* If you want to check that you uploaded your key correctly, you can do so by issuing this:
```bash
aws s3 cp s3://as24-ssh-access-<REGION>/<ACCOUNT_ID>/<SERVICE>/<AWS_USERNAME> <SOME FILENAME>
```
so for example:
```bash
aws s3 cp s3://as24-ssh-access-eu-west-1/544725753551/log2es-kibana/jfeilen jfeilen
```
* Although my MFA token is valid, I get one of this error messages:



* If you have any problems upgrading the iam-bash pls refer to the [issue](https://github.com/AutoScout24/iam-bash/issues/13) we had. Basic idea is to remove the old artifacts and to configure the newest one.
* If your upload is denied make sure you have the iam_mfa credentions loaded. This should output 1:
```bash
cat ~/.aws/credentials | grep iam_mfa | wc -l
```
If it is not one, please assume a role to get the credentials set:
```bash
aws_assume as24dev PowerUserAccess
```
