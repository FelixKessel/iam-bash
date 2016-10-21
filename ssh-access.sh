#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "as24-ssh-access.sh [SERVICE NAME] [ACCOUNT NAME] [AWS_REGION] [SSH PUBLIC KEY FILE] [USERNAME]"
    exit 0
fi

SSH_BUCKET="as24-ssh-access"

SERVICE_NAME=$1

# get the full script path
if test -n "$BASH_VERSION"; then
  SCRIPT_FULL_PATH=${BASH_SOURCE[0]}
else
  SCRIPT_FULL_PATH=${(%):-%x}[0]
fi

# locate lookup file of all our AWS accounts with their Account IDs
SCRIPT_PATH=$(dirname ${SCRIPT_FULL_PATH})
AS24_AWS_ACCOUNTS_FILE=${SCRIPT_PATH}/as24-aws-accounts.txt

# check if REQUESTED_ACCOUNT_NAME is valid
if [ ! -z "${REQUESTED_ACCOUNT_NAME}" ]; then
  ACCOUNT_NAME_IN_FILE=$(grep -c -e "${REQUESTED_ACCOUNT_NAME}:" ${AS24_AWS_ACCOUNTS_FILE})
  if [ "${ACCOUNT_NAME_IN_FILE}" -eq "0" ]; then
    echo "Error: the argument \"${REQUESTED_ACCOUNT_NAME}\" does not seem to be a valid AS24 account"
    return 1
  fi
fi

# Get value by key (like associative array)
_get() {
  echo $(grep -e "${2}\:" ${AS24_AWS_ACCOUNTS_FILE} | cut -f2 -d":")
}

detect_keytype() {
  local keyfile="${1}"

  if [ -f ${keyfile} ] ; then
    read -r firstline<$keyfile
    if [[ $firstline == *PRIVATE* ]] ; then
      echo "The key file you specified is a private key! Please specify a PUBLIC KEY file."
      exit 1
    fi
  fi
}

validate_public_key() {
  local key="$1"
  local key_info="`ssh-keygen -l -f ${key}`"
  local key_type="`awk -F \"[()]\" '{print $2}' <<< ${key_info}`"

  # We want either ED25519 keys or RSA keys with >= 4096 bits
  if [ "${key_type}" == "RSA" ] ; then
    if [ "${key_info%%\ *}" -lt 4096 ] ; then
      echo "Your RSA key doesn't have the required bit size of 4096."
      exit 1
    fi
  elif ! [ "${key_type}" == "ED25519" ] ; then
    echo "Your key is either not an RSA key with 4096bits or a ED25519 key. Aborted."
    exit 1
  fi
}

AWSACCOUNTID=$(_get AS24_AWS_ACCOUNTS $2)

# set the region
if [ -z $3 ]
	then
		if [ -z $AWS_DEFAULT_REGION ]
			then
				AWS_REGION="eu-west-1"
			else
				AWS_REGION=$AWS_DEFAULT_REGION
			fi
	else
		AWS_REGION=$3
fi


# Get the SSH key
if [ -z $4 ]
	then
		if [ -e "$HOME/.ssh/id_rsa.pub" ]
			then
				echo "using default key at ~/.ssh/id_rsa.pub"
				SSH_KEY_FILEPATH="$HOME/.ssh/id_rsa.pub"
    elif [ -e "$HOME/.ssh/id_ed25519.pub" ]
      then
        echo "using default key at ~/.ssh/id_ed25519.pub"
				SSH_KEY_FILEPATH="$HOME/.ssh/id_ed25519.pub"
			else
				echo "no ssh pulic key found"
				exit 1
		fi
	else
		if [ ! -e $4 ]
			then
				echo "SSH key file not found"
				exit 1
			else
				SSH_KEY_FILEPATH=$4
		fi
fi

detect_keytype "${SSH_KEY_FILEPATH}"
validate_public_key "${SSH_KEY_FILEPATH}"

# get username
if [ -z $5 ]
    then
        # if global variable AS24_AWS_IAM_USER not defined then will use shell username
        if [ -z "$AS24_AWS_IAM_USER" ]
            then
                USERNAME="$(id -un)"
            else
                USERNAME="$AS24_AWS_IAM_USER"
        fi
    else
        USERNAME=$5
fi

# to lower case
USERNAME=`echo $USERNAME | tr '[:upper:]' '[:lower:]'`
{
  # upload file to S3
  aws s3 cp $SSH_KEY_FILEPATH s3://${SSH_BUCKET}-${AWS_REGION}/${AWSACCOUNTID}/bastion-host/${USERNAME} --profile "as24iam_mfa"
  aws s3 cp $SSH_KEY_FILEPATH s3://${SSH_BUCKET}-${AWS_REGION}/${AWSACCOUNTID}/${SERVICE_NAME}/${USERNAME} --profile "as24iam_mfa"
} || {
  echo "something went wrong, to get help please visit: https://github.com/AutoScout24/iam-bash#faq"
}

exit 0
