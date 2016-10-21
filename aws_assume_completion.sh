#!/bin/bash

if test -n "$BASH_VERSION"; then
  SCRIPT_FULL_PATH=${BASH_SOURCE[0]}
else
  SCRIPT_FULL_PATH=${(%):-%x}[0]
fi

# locate lookup file of all our AWS accounts with their Account IDs
SCRIPT_PATH=$(dirname ${SCRIPT_FULL_PATH})

_aws_assume()
{
    local CUR PREV OPTS ACCOUNTS ROLES
    COMPREPLY=()
    CUR="${COMP_WORDS[COMP_CWORD]}"
    PREV="${COMP_WORDS[COMP_CWORD-1]}"
    OPTS="--unassume --reset --help --variables --rotate-keys"
    ACCOUNTS=$(awk -F":" '{print $1}' ${SCRIPT_PATH}/as24-aws-accounts.txt)
    ROLES="PowerUserAccess ReadOnlyAccess"

    IFS=', ' read -r -a ACCOUNTS_ARRAY <<< "$ACCOUNTS"

    for COMP_WORD in "${COMP_WORDS[@]}" ; do
      for ACCOUNT in "${ACCOUNTS_ARRAY[@]}" ; do
        if [[ "${ACCOUNT}" == "${COMP_WORD}" ]] ; then
          local HAS_ACCOUNT=true
        fi
      done
    done

    if [[ ${CUR} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${OPTS}" -- ${CUR}) )
        return 0
    elif [[ ${HAS_ACCOUNT} ]] ; then
      COMPREPLY=( $(compgen -W "${ROLES}" -- ${CUR}) )
      return 0
    else
      COMPREPLY=( $(compgen -W "${ACCOUNTS}" -- ${CUR}) )
      return 0
    fi
}
complete -F _aws_assume aws_assume
