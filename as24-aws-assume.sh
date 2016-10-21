#!/bin/bash

# This Script should only be sourced
if test -n "$BASH_VERSION" && [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "Error: This script should only be souced, as it needs to set global Shell variables"
  echo "       Please run with \"source $(basename -- "$0")\" instead of \"$0\""
  exit 1
fi

# check that the aws cli is installed
if [ ! $(which aws) ]; then
  echo "Error: AWS CLI is required"
  exit 1
fi

# test the version of the aws cli
AWSCLIVERS=$(aws --version | cut -f2 -d\/ | cut -f1 -d\  )

# get the full script path
if test -n "$BASH_VERSION"; then
  SCRIPT_FULL_PATH=${BASH_SOURCE[0]}
else
  SCRIPT_FULL_PATH=${(%):-%x}[0]
fi

# locate lookup file of all our AWS accounts with their Account IDs
SCRIPT_PATH=$(dirname ${SCRIPT_FULL_PATH})
export AS24_AWS_ACCOUNTS_FILE=${SCRIPT_PATH}/as24-aws-accounts.txt

# Set a timestamp for now
TIMESTAMP_NOW="$(date '+%s')"

# Set as24 access key rotation warning interval to 7 days:
export AS24_KEY_ROTATION_WARNING_INTERVAL="604800"
# 30 days
export AS24_KEY_ROTATION_EXPIRY_INTERVAL="2592000"

##############################################
# Interpret command arguments- set switches  #
##############################################
unset SHOW_STATUS AS24_AWS_UNASSUME AS24_AWS_RESET SHOW_HELP SHOW_VARIABLES ROTATE_KEYS CHECK_MFA ASSUME_ROLE SET_AWS_VARIABLES REQUESTED_ACCOUNT_NAME REQUESTED_ROLE
if [ "$#" -eq "0" ]; then SHOW_STATUS=true; CHECK_MFA=true; SET_AWS_VARIABLES=true; else
  trap "echo Error in the main script case clause; return 1" ERR
  case "$1" in
    --unassume|-u )   AS24_AWS_UNASSUME=true ;;
    --reset )         AS24_AWS_RESET=true ;;
    --help|-h )       SHOW_HELP=true ;;
    --variables|-v )  SHOW_VARIABLES=true ;;
    --rotate-keys )   ROTATE_KEYS=true ;;
    -*)               echo "Error: Please check if \"$@\" are correct parameters for this script." ;;
    * )               REQUESTED_ACCOUNT_NAME=${1}
                      REQUESTED_ROLE=${2:-ReadOnlyAccess}
                      CHECK_MFA=true
                      ASSUME_ROLE=true ;;
  esac
  trap - ERR
fi

#####################################################
# Adds deprecated aws_security_token                #
# https://github.com/AutoScout24/iam-bash/issues/16 #
#####################################################

function  add_aws_security_token_for_boto {
    [ -f ~/.aws/credentials.for_boto ] && rm ~/.aws/credentials.for_boto

    while IFS= read -r line; do
        if [[ ! $line =~ "aws_security_token" ]]; then
            echo $line >> ~/.aws/credentials.for_boto
        fi
        
        if [[ $line =~ ^aws_session_token.* ]];then      
            echo $line | sed 's/aws_session_token/aws_security_token/g'  >> ~/.aws/credentials.for_boto
        fi    
    done <~/.aws/credentials

    mv ~/.aws/credentials.for_boto ~/.aws/credentials
}

###################
# Show Help       #
###################
if [ ${SHOW_HELP} ]; then
  trap "echo Error in SHOW_HELP; return 1" ERR
  SCRIPTNAME=$(basename -- "${BASH_SOURCE[0]}")
  echo "\
Usage:
  source $SCRIPTNAME ACCOUNT [ROLE]
     - assumes an AS24 AWS ROLE with the ACCOUNT specified
     - if an as24-AWS-Role is not specified, then \"ReadOnlyAccess\" will be attempted
Examples:
  source $SCRIPTNAME as24dev PowerUserAccess
  source $SCRIPTNAME as24prod ReadOnlyAccess
  source $SCRIPTNAME as24prod
Other Options:
  source $SCRIPTNAME --unassume or -u     unassume any assumed roles
  source $SCRIPTNAME --variables or -v    show all AS24 AWS variables set using this tool
  source $SCRIPTNAME --reset              remove all variables set using this tool
  source $SCRIPTNAME --rotate-keys        rotate the AWS keys currently set in ~/.aws/credentials [as24iam]
Notes:
- This utility relies on having an AS24 AWS credentials profile in place.
- Setting up the basic AWS credentials and default config can be done by running the following command:
    aws configure --profile as24iam
- This command will prompt you for:
      AWS Access Key ID
      AWS Secret Access Key
      Default region name (eg eu-west-1, optional)
      Default output format (text|json, optional)
- These values will then be saved in the config and credentials files in the ~/.aws/ user directory.
- Run the following command for more information on AWS credentials:
    aws configure help"
  trap - ERR
  return
fi

##############################################
# Reset all AS24 AWS Session variables       #
##############################################
if [ ${AS24_AWS_RESET} ]; then
  trap "echo Error in AS24_AWS_RESET; return 1" ERR
  echo "# Resetting all variables used by this script..."
  unset AS24_AWS_PROFILE
  unset AS24_AWS_TOKEN_DURATION
  unset AS24_AWS_DEFAULT_REGION
  unset AS24_AWS_IAM_ACCOUNT_NAME
  unset AS24_AWS_IAM_ACCOUNT_ID
  unset AS24_PROFILE_AWS_ACCESS_KEY_ID
  unset AS24_PROFILE_AWS_SECRET_ACCESS_KEY
  unset AS24_PROFILE_AWS_ARN
  unset AS24_PROFILE_AWS_ID
  unset AS24_PROFILE_AWS_USERNAME
  unset AS24_PROFILE_AWS_SERIALNUMBER
  unset AS24_PROFILE_AWS_KEY_CREATIONDATE
  unset AS24_PROFILE_AWS_KEY_TIMESTAMP
  unset AS24_MFA_AWS_ACCESS_KEY_ID
  unset AS24_MFA_AWS_SECRET_ACCESS_KEY
  unset AS24_MFA_AWS_SESSION_TOKEN
  unset AS24_MFA_AWS_TOKEN_EXPIRATION
  unset AS24_MFA_AWS_TOKEN_TIMESTAMP
  unset AWS_ACCESS_KEY_ID
  unset AWS_SECRET_ACCESS_KEY
  unset AWS_SESSION_TOKEN
  unset AWS_DEFAULT_REGION
  unset AS24_AWS_ASSUME_ACCOUNT
  unset AS24_AWS_ASSUME_ROLE
  trap - ERR
  return
fi


########################################################
# Check AWS Configuration and Requested Account Name   #
########################################################
# Setup global variables for using the AS24_PROFILE keys
export AS24_AWS_PROFILE="as24iam"
export AS24_AWS_MFA_PROFILE="as24iam_mfa"

# check if REQUESTED_ACCOUNT_NAME is valid
if [ ! -z "${REQUESTED_ACCOUNT_NAME}" ]; then
  ACCOUNT_NAME_IN_FILE=$(grep -c -e "${REQUESTED_ACCOUNT_NAME}:" ${AS24_AWS_ACCOUNTS_FILE})
  if [ "${ACCOUNT_NAME_IN_FILE}" -eq "0" ]; then
    echo "Error: the argument \"${REQUESTED_ACCOUNT_NAME}\" does not seem to be a valid AS24 account"
    return 1
  fi
fi

# setup the correct switches for the date command, if running on MacOS
if [ "$(uname)" = "Darwin" ]; then
  DATE_CONV_PARAM='-ju -f %Y-%m-%dT%H:%M:%SZ'
else
# otherwise just use the Linux default
  DATE_CONV_PARAM='-d'
fi

# setup the correct array base for zsh compatibility
# if using the Z Shell...
if test -n "${ZSH_VERSION}"; then
  SHELL_ARRAY_BASE=1
else
# Oterwise, we assume using bash
  SHELL_ARRAY_BASE=0
fi

# Test to see if the AS24_PROFILE has been setup in the ~/.aws/ config folder
aws configure get aws_access_key_id --profile ${AS24_AWS_PROFILE} > /dev/null
if [ $? -ne 0 ] || \
   [ ! -f ~/.aws/config ] || \
   [ ! -f ~/.aws/credentials ]; then
  echo "Error: AWS authentication keys are not available."
  echo "       To install your AWS Keys in the \"~/.aws/\" directory, run:    "
  echo "         aws configure --profile ${AS24_AWS_PROFILE}"
  return 1
fi

#########################################
# Setup global base variables and data  #
#########################################
# Create base variables, if they are not already available
if [ -z "${AS24_PROFILE_AWS_ACCESS_KEY_ID}" ] || \
   [ -z "${AS24_PROFILE_AWS_SECRET_ACCESS_KEY}" ]; then
  trap "echo Error while setting global AS24 AWS variables; return 1" ERR
  echo "# Loading AS24 AWS Key metadata..."
  export AS24_AWS_TOKEN_DURATION="3600"
  export AS24_AWS_DEFAULT_REGION=$(aws configure get region --profile "default")
  export AS24_AWS_DEFAULT_REGION=$([ $AS24_AWS_DEFAULT_REGION == "" ] && echo $AS24_AWS_DEFAULT_REGION || echo "eu-west-1")
  # Set variables for AS24 IAM Account
  export AS24_AWS_IAM_ACCOUNT_NAME="as24iam"
  export AS24_AWS_IAM_ACCOUNT_ID=$(grep -e "${AS24_AWS_IAM_ACCOUNT_NAME}\:" ${AS24_AWS_ACCOUNTS_FILE} | cut -f2 -d":")
  # Set variables for AS24 Profile IAM AWS Key
  export AS24_PROFILE_AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id --profile ${AS24_AWS_PROFILE})
  export AS24_PROFILE_AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key --profile ${AS24_AWS_PROFILE})
  export AS24_PROFILE_AWS_ARN=$(aws iam get-user --query '[User.Arn]' --profile ${AS24_AWS_PROFILE} --output text)
  export AS24_PROFILE_AWS_ID=$(echo ${AS24_PROFILE_AWS_ARN} | cut -d \: -f 5)
  export AS24_PROFILE_AWS_USERNAME=$(echo ${AS24_PROFILE_AWS_ARN} | rev | cut -d \/ -f 1 | rev)
  export AS24_PROFILE_AWS_SERIALNUMBER="arn:aws:iam::${AS24_AWS_IAM_ACCOUNT_ID}:mfa/${AS24_PROFILE_AWS_USERNAME}"
  # If you have a hardware devices, set this variable with your MFA serial number, otherwise leave commented
  # export AS24_PROFILE_AWS_SERIALNUMBER="GAKTxxxxx"  export AS24_PROFILE_AWS_SERIALNUMBER="arn:aws:iam::${AS24_AWS_IAM_ACCOUNT_ID}:mfa/${AS24_PROFILE_AWS_USERNAME}"
  export AS24_PROFILE_AWS_KEY_CREATIONDATE=$(aws iam list-access-keys --query '[AccessKeyMetadata[*].{CD:CreateDate}]' \
     --profile ${AS24_AWS_PROFILE} --output text)
  export AS24_PROFILE_AWS_KEY_TIMESTAMP=$(date ${DATE_CONV_PARAM} "${AS24_PROFILE_AWS_KEY_CREATIONDATE}" '+%s' )
  SHOW_STATUS=true
  #$AS24_AWS_PROFILE --output text | grep "$AS24_AWS_IAM_USER_ACCESS_KEY_ID" | cut -f2)
  export AWS_ACCESS_KEY_ID=${AS24_PROFILE_AWS_ACCESS_KEY_ID}
  export AWS_SECRET_ACCESS_KEY=${AS24_PROFILE_AWS_SECRET_ACCESS_KEY}
  export AWS_DEFAULT_REGION=${AS24_AWS_DEFAULT_REGION}
  trap - ERR
fi

######################################
# Rotate the key if expired          #
######################################
# Ask if key should be rotated in case it's enabled and the interval has been reached
if [ ${ROTATE_KEYS} ] || \
   [ "${AS24_PROFILE_AWS_KEY_TIMESTAMP}" -lt "$(( $(date '+%s') - ${AS24_KEY_ROTATION_EXPIRY_INTERVAL} ))" ]; then
  trap "echo Error in ROTATE_KEYS; return 1" ERR
  echo -n "$(echo "Your access key should be rotated. Rotate now? (y/n)") "
  read resp
  if [ "$resp" = "y" ]; then
    #_rotate_key
    # Create a new access key
    echo "# Creating new access key..."
    # KS=access*K*ey, *S*ecretkey
    KS=($(aws iam create-access-key \
           --user-name "${AS24_PROFILE_AWS_USERNAME}" \
           --query '[AccessKey.AccessKeyId,AccessKey.SecretAccessKey]' \
           --profile "${AS24_AWS_PROFILE}" \
           --output text))
    # Temporarily store the old key ID
    OLD_KEY=${AS24_PROFILE_AWS_ACCESS_KEY_ID}
    # Replace the old key details with the new
    export AS24_PROFILE_AWS_ACCESS_KEY_ID=${KS[0 + SHELL_ARRAY_BASE]}
    export AS24_PROFILE_AWS_SECRET_ACCESS_KEY=${KS[1 + SHELL_ARRAY_BASE]}
    # Show progress
    echo "# New access key id: ${AS24_PROFILE_AWS_ACCESS_KEY_ID}"
    echo "# Saving new access key in the AWS profile..."
    # Store the new keys in the credentials file profile
    aws configure set aws_access_key_id "${AS24_PROFILE_AWS_ACCESS_KEY_ID}" --profile ${AS24_AWS_PROFILE}
    aws configure set aws_secret_access_key "${AS24_PROFILE_AWS_SECRET_ACCESS_KEY}" --profile ${AS24_AWS_PROFILE}
    # Delete the old key
    echo "# Deleting old access key ${OLD_KEY} - this takes 10 seconds to sync ..."
    sleep 10
    aws iam delete-access-key \
      --access-key-id "${OLD_KEY}" \
      --profile "${AS24_AWS_PROFILE}"
    trap - ERR
  else
    # Checking for expiring keys.
    dateOfExpiry=$(( ${AS24_PROFILE_AWS_KEY_TIMESTAMP} + ${AS24_KEY_ROTATION_EXPIRY_INTERVAL}))
    dateOfWarningStart=$((${dateOfExpiry} - ${AS24_KEY_ROTATION_WARNING_INTERVAL}))

    if [ "${dateOfWarningStart}" -lt "$(( $(date '+%s')))" ]; then
      echo "Your access key is about to expire soon. Please consider rotating your key with aws_assume --rotate-keys";
      echo "Please keep in mind that access keys older than 30 days will be deleted automatically.";
    fi
  fi
fi

#################################################
# Ensure valid MFA Session Token is available   #
#################################################
if [ ${CHECK_MFA} ]; then
  trap "echo Error in CHECK_MFA; return 1" ERR
  if [ -z "${AS24_MFA_AWS_TOKEN_TIMESTAMP}" ] || \
     [ "${AS24_MFA_AWS_TOKEN_TIMESTAMP}" -lt "${TIMESTAMP_NOW}" ]; then
    # Setup variables for current MFA Session Token
    # Prompt for MFA token
    echo -n "$(echo "# Enter MFA token code:") "
    read MFA_TOKEN_CODE
    # Setup an MFA Session Token
    # KSTE=access*K*ey, *S*ecretkey, session*T*oken, *E*xpiration
    KSTE=($(aws sts get-session-token \
             --duration "${AS24_AWS_TOKEN_DURATION}" \
             --serial-number "${AS24_PROFILE_AWS_SERIALNUMBER}" \
             --token-code "${MFA_TOKEN_CODE}" \
             --query \
             '[Credentials.AccessKeyId,Credentials.SecretAccessKey,Credentials.SessionToken,Credentials.Expiration]' \
             --profile "${AS24_AWS_PROFILE}" \
             --output text))
    # Set the Variables for current MFA Session Token
    export AS24_MFA_AWS_ACCESS_KEY_ID=${KSTE[0 + SHELL_ARRAY_BASE]}
    export AS24_MFA_AWS_SECRET_ACCESS_KEY=${KSTE[1 + SHELL_ARRAY_BASE]}
    export AS24_MFA_AWS_SESSION_TOKEN=${KSTE[2 + SHELL_ARRAY_BASE]}
    export AS24_MFA_AWS_TOKEN_EXPIRATION=${KSTE[3 + SHELL_ARRAY_BASE]}
    export AS24_MFA_AWS_TOKEN_TIMESTAMP=$(date ${DATE_CONV_PARAM} "${AS24_MFA_AWS_TOKEN_EXPIRATION}" '+%s')
    aws configure set aws_access_key_id "${AS24_MFA_AWS_ACCESS_KEY_ID}" --profile "${AS24_AWS_MFA_PROFILE}"
    aws configure set aws_secret_access_key "${AS24_MFA_AWS_SECRET_ACCESS_KEY}" --profile "${AS24_AWS_MFA_PROFILE}"
    aws configure set aws_session_token "${AS24_MFA_AWS_SESSION_TOKEN}" --profile "${AS24_AWS_MFA_PROFILE}"
    add_aws_security_token_for_boto
    export AS24_AWS_ACCOUNT_NAME=""
    export AS24_AWS_ACCOUNT_ID=""
    SHOW_STATUS=true
  fi
  trap - ERR
fi

######################################
# Assume Role                        #
######################################
if [ ${ASSUME_ROLE} ]; then
  trap "echo Error in ASSUME_ROLE; return 1" ERR
  #trap - ERR

  # Assume a role with the parameters given to the command
  REQUESTED_ACCOUNT_ID="$(grep "${REQUESTED_ACCOUNT_NAME}\:" "${AS24_AWS_ACCOUNTS_FILE}" | cut -f2 -d":")"
  #echo "User ${AS24_AWS_IAM_ACCOUNT_NAME}/${AS24_PROFILE_AWS_USERNAME} assuming role ${REQUESTED_ROLE} in account ${REQUESTED_ACCOUNT_NAME} (ID ${REQUESTED_ACCOUNT_ID})"
  # set special aws variables to the currently active MFA session token before using aws command
  export AWS_ACCESS_KEY_ID=${AS24_MFA_AWS_ACCESS_KEY_ID}
  export AWS_SECRET_ACCESS_KEY=${AS24_MFA_AWS_SECRET_ACCESS_KEY}
  export AWS_SESSION_TOKEN=${AS24_MFA_AWS_SESSION_TOKEN}
  export AWS_DEFAULT_REGION=${AS24_AWS_DEFAULT_REGION}
  # attempt to switch AWS roles
  # KST=access*K*ey, *S*ecretkey, session*T*oken
  KST=($(aws sts assume-role --role-arn arn:aws:iam::${REQUESTED_ACCOUNT_ID}:role/${REQUESTED_ROLE} \
    --role-session-name ${AS24_PROFILE_AWS_USERNAME} \
    --duration-seconds ${AS24_AWS_TOKEN_DURATION} \
    --query '[Credentials.AccessKeyId,Credentials.SecretAccessKey,Credentials.SessionToken]' \
    --output text))
  export AWS_ACCESS_KEY_ID=${KST[0 + $SHELL_ARRAY_BASE]}
  export AWS_SECRET_ACCESS_KEY=${KST[1 + $SHELL_ARRAY_BASE]}
  export AWS_SESSION_TOKEN=${KST[2 + $SHELL_ARRAY_BASE]}
  # setup an aws profile with the temporary key
  aws configure set aws_access_key_id "${AWS_ACCESS_KEY_ID}" --profile "${REQUESTED_ACCOUNT_NAME} ${REQUESTED_ROLE}"
  aws configure set aws_secret_access_key "${AWS_SECRET_ACCESS_KEY}" --profile "${REQUESTED_ACCOUNT_NAME} ${REQUESTED_ROLE}"
  aws configure set aws_session_token "${AWS_SESSION_TOKEN}" --profile "${REQUESTED_ACCOUNT_NAME} ${REQUESTED_ROLE}"
  add_aws_security_token_for_boto
  # Store which AWS account and role have been set
  AS24_AWS_ASSUME_ACCOUNT=${REQUESTED_ACCOUNT_NAME}
  AS24_AWS_ASSUME_ROLE=${REQUESTED_ROLE}
  SHOW_STATUS=true
  trap - ERR
fi

#########################
# Unassume Role         #
#########################
# Unset the variables which set the default keys for connecting with the "aws" command
if [ ${AS24_AWS_UNASSUME} ]; then
  export AWS_ACCESS_KEY_ID=${AS24_PROFILE_AWS_ACCESS_KEY_ID}
  export AWS_SECRET_ACCESS_KEY=${AS24_PROFILE_AWS_SECRET_ACCESS_KEY}
  unset AWS_SESSION_TOKEN
  unset AS24_AWS_ASSUME_ACCOUNT
  unset AS24_AWS_ASSUME_ROLE
  SHOW_STATUS=true
fi

###################################
# Set AWS variables to MFA ones   #
###################################
if [ ${SET_AWS_VARIABLES} ]; then
  export AWS_ACCESS_KEY_ID=${AS24_MFA_AWS_ACCESS_KEY_ID}
  export AWS_SECRET_ACCESS_KEY=${AS24_MFA_AWS_SECRET_ACCESS_KEY}
  export AWS_SESSION_TOKEN=${AS24_MFA_AWS_SESSION_TOKEN}
fi

##############################
# Show Status                #
##############################
if [ ${SHOW_STATUS} ]; then
  dateOfExpiry=$(( ${AS24_PROFILE_AWS_KEY_TIMESTAMP} + ${AS24_KEY_ROTATION_EXPIRY_INTERVAL}))
  dateOfWarningStart=$((${dateOfExpiry} - ${AS24_KEY_ROTATION_WARNING_INTERVAL}))

  if [ "${dateOfWarningStart}" -lt "$(( $(date '+%s')))" ]; then
    echo "Your access key is about to expire soon. Please consider rotating your key with aws_assume --rotate-keys";
    echo "Please keep in mind that access keys older than 30 days will be deleted automatically.";
  fi

  if [ -z "${AWS_SECRET_ACCESS_KEY}" ]; then echo "# AWS Profile: ${AS24_AWS_PROFILE} (see ~/.aws/credentials)"; fi
  if [ ! -z "${AS24_MFA_AWS_ACCESS_KEY_ID}" ];     then echo "# MFA token:   active"; else echo "# MFA token:   inactive"; fi
  if [ ! -z "${AS24_AWS_ASSUME_ACCOUNT}" ];        then echo "# Account:     ${AS24_AWS_ASSUME_ACCOUNT}";  echo "# Role:        ${AS24_AWS_ASSUME_ROLE}"; fi
fi

######################################
# Show All Variables                 #
######################################
# Show all variables used to setup MFA Session Tokens and assume other roles
if [ ${SHOW_VARIABLES} ]; then
  echo "# Variables being currently exported:"
  echo "# Note: currently using aws cli version ${AWSCLIVERS} - should be greater than 1.10"
  echo export AS24_AWS_PROFILE=\"${AS24_AWS_PROFILE}\"
  echo export AS24_AWS_TOKEN_DURATION=\"${AS24_AWS_TOKEN_DURATION}\"
  echo export AS24_AWS_DEFAULT_REGION=\"${AS24_AWS_DEFAULT_REGION}\"
  echo export AS24_AWS_IAM_ACCOUNT_NAME=\"${AS24_AWS_IAM_ACCOUNT_NAME}\"
  echo export AS24_AWS_IAM_ACCOUNT_ID=\"${AS24_AWS_IAM_ACCOUNT_ID}\"
  echo export AS24_PROFILE_AWS_ACCESS_KEY_ID=\"${AS24_PROFILE_AWS_ACCESS_KEY_ID}\"
  echo export AS24_PROFILE_AWS_SECRET_ACCESS_KEY=\"${AS24_PROFILE_AWS_SECRET_ACCESS_KEY}\"
  echo export AS24_PROFILE_AWS_ARN=\"${AS24_PROFILE_AWS_ARN}\"
  echo export AS24_PROFILE_AWS_ID=\"${AS24_PROFILE_AWS_ID}\"
  echo export AS24_PROFILE_AWS_USERNAME=\"${AS24_PROFILE_AWS_USERNAME}\"
  echo export AS24_PROFILE_AWS_SERIALNUMBER=\"${AS24_PROFILE_AWS_SERIALNUMBER}\"
  echo export AS24_PROFILE_AWS_KEY_CREATIONDATE=\"${AS24_PROFILE_AWS_KEY_CREATIONDATE}\"
  echo export AS24_PROFILE_AWS_KEY_TIMESTAMP=\"${AS24_PROFILE_AWS_KEY_TIMESTAMP}\"
  echo export AS24_MFA_AWS_ACCESS_KEY_ID=\"${AS24_MFA_AWS_ACCESS_KEY_ID}\"
  echo export AS24_MFA_AWS_SECRET_ACCESS_KEY=\"${AS24_MFA_AWS_SECRET_ACCESS_KEY}\"
  echo export AS24_MFA_AWS_SESSION_TOKEN=\"${AS24_MFA_AWS_SESSION_TOKEN}\"
  echo export AS24_MFA_AWS_TOKEN_EXPIRATION=\"${AS24_MFA_AWS_TOKEN_EXPIRATION}\"
  echo export AS24_MFA_AWS_TOKEN_TIMESTAMP=\"${AS24_MFA_AWS_TOKEN_TIMESTAMP}\"
  echo export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"
  echo export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"
  echo export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\"
  echo export AWS_DEFAULT_REGION=\"${AWS_DEFAULT_REGION}\"
  echo export AS24_AWS_ASSUME_ACCOUNT=\"${AS24_AWS_ASSUME_ACCOUNT}\"
  echo export AS24_AWS_ASSUME_ROLE=\"${AS24_AWS_ASSUME_ROLE}\"
  return
fi

trap - ERR
