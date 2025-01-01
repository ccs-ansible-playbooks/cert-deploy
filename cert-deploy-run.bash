#!/bin/bash

export FROM_ADDRESS="letsencrypt-alert@centennialchristian.ca"
export FROM_NAME="LetsEncrypt Cert Alert"

MSMTP_ACCOUNT="internalrelay"
PLAYBOOK_DEPLOY_NAME="cert-deploy-all.yml"
PLAYBOOK_FETCH_NAME="cert-fetch.yml"
SECRETS_FILE="secrets/secrets.yml"
#TO_ADDRESS="Notifications@centennialchristian.ca"
TO_ADDRESS="erolleman@outlook.com"

script_dir=$(dirname "$0")
template_failed_email="${script_dir}/failed-email.template.html"

cleanup() {
    test -f "${playbook_results}" && rm -f "${playbook_results}"
}

trap "cleanup; exit" 1 2 3 6 14 15

# The email used to inform of failures is derived from a template that subsitutes
#   environtment variables. Creating the environment variables here that will be
#   necessary for the substitution
export computer_name=$(hostnamectl hostname)
while IFS=$'\n' read -r row; do
    export ip_address_table=$(printf "${ip_address_table}\n    <tr>${row}</tr>")
done <<<"$(ip -brief address | awk '$1!~"^lo" {print "<td>",$1,"</td>","<td>",$3,"</td>"}')"
export script_full_path=$(realpath $0)

secrets_path="${script_full_path}/${SECRETS_FILE}"

if [ ! -f "${secrets_path}" ]; then
    failed_msg=$(cat<<EOF
The file '${secrets_path}' is missing.
Please use '${secrets_path}.example' as a reference to create the file.
This file must have read + write permissions for user only. Use the following
command to set permissions on the new file after it is created:
    sudo chmod 0600 "${secrets_path}"
EOF
)
    echo "ERROR: ${failed_msg}" >&2
    export failed_html_out=$(echo "${failed_msg}" | sed -e 's/$/<br \/>/')
    cat "${script_dir}/failed-email.template.html" | \
        envsubst | \
        msmtp --account="${MSMTP_ACCOUNT}" "{{ TO_ADDRESS }}"

    exit 10
fi

# make sure that permissions are setup correctly: only owner should have permissions
if ! stat -c %A "${secrets_path}" | grep -E "^[\-Srwx]{3}[\-]{6}\$"; then
    failed_msg=$(cat<<EOF
Incorrect permissions set on '${secrets_path}'.
Correct the permissions with this command:
    sudo chmod 0600 "${secrets_path}"
EOF
)
    echo "ERROR: ${failed_msg}" >&2
    export failed_html_out=$(echo "${failed_msg}" | sed -e 's/$/<br \/>/')
    cat "${script_dir}/failed-email.template.html" | \
        envsubst | \
        msmtp --account="${MSMTP_ACCOUNT}" "{{ TO_ADDRESS }}"

    exit 11
fi

echo "Ending early"; exit;
echo "Running playbook"

playbook_results=$(ansible-playbook -e "smtp_from_name=${FROM_NAME}" -e "smtp_from_address=${FROM_ADDRESS}" -e "smtp_to=${TO_ADDRESS}" -u ansibleadmin -b "${script_dir}/${PLAYBOOK_FETCH_NAME}" "${script_dir}/${PLAYBOOK_DEPLOY_NAME}" 2>&1)
exit_code=$?
echo "${playbook_results}"

if [ $exit_code != 0 ]; then
    echo "There was an error deploying certificate files!" >&2

    export failed_html_out=$(echo "${playbook_results}" | sed -e 's/$/<br \/>/')

    cat "${script_dir}/failed-email.template.html" | \
        envsubst | \
        msmtp --account="${MSMTP_ACCOUNT}" it-dept@sd87.bc.ca
    exit $exit_code

    del computer_name
    del ip_address_table
    del playbook_results_for_email
    del script_full_path
fi



