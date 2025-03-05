#!/bin/bash

FROM_ADDRESS="NetworkNotifications@centennialchristian.ca"
FROM_NAME="LetsEncrypt Cert Alert"

PLAYBOOK_DEPLOY_NAME="cert-deploy-all.yml"
PLAYBOOK_FETCH_NAME="cert-fetch.yml"
SECRETS_FILE="secrets/secrets.yml"
TO_ADDRESS="Notifications@centennialchristian.ca"
# TO_ADDRESS="erolleman@outlook.com"

script_dir=$(dirname "$0")
# file created by playbook if a new certificate was fetched
notify_file_path="${script_dir}/fetched_new_cert"
template_failed_email="${script_dir}/failed-email.template.html"

IP_ADDR_TO_JSON_AWK=$(cat<<EOF
BEGIN {
    printf "[ " 
    counter=0
}

{
    if (\$1 !~ /lo/) {
        counter=counter+1
        if (counter > 1) {
            printf ", "
        }
        printf "{\"name\": \"" \$1 "\", \"address\": \"" \$3 "\"}"
    }
}

END {
    printf " ]"
}
EOF
)

cleanup() {
    test -f "${playbook_results}" && \
        rm -f "${playbook_results}"
}

email_failure() {
    local playbook_output="${1}"
    failed_html_out=$(echo "${playbook_output}" | sed -e 's/$/<br \/>/')

    sendmail -t < <( \
        jinja2 \
            -D "FROM_ADDRESS=${FROM_ADDRESS}" \
            -D "FROM_NAME=${FROM_NAME}" \
            -D "computer_name=$(hostnamectl hostname)" \
            -D "ip_address_table=$(ip -br addr | awk "${IP_ADDR_TO_JSON_AWK}")" \
            -D "fail_html_out=$(echo "${playbook_output}" | sed -e 's/$/<br \/>/')")    

    cat "${template_failed_email}" | \
        envsubst | \
        msmtp --account="${MSMTP_ACCOUNT}" it-dept@sd87.bc.ca

    unset playbook_output
    unset failed_html_out
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

secrets_path="${script_dir}/${SECRETS_FILE}"

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
        mailx -s "LetsEncrypt cert deployment failure"
        msmtp --account="${MSMTP_ACCOUNT}" "{{ TO_ADDRESS }}"

    exit 11
fi

# remove file that indicates there is a new cert file if it already exists
[ -f "${notify_file_path}" ] && rm -f "${notify_file_path}"
echo "Running fetch playbook"

fetch_playbook_results=$(ansible-playbook -u ansibleadmin -b "${script_dir}/${PLAYBOOK_FETCH_NAME}" 2>&1)
exit_code=$?
echo "${fetch_playbook_results}"

if [ $exit_code != 0 ]; then
    echo "There was an error fetching certificate files!" >&2    
    email_failure "${fetch_playbook_results}"
    exit $exit_code

fi
unset fetch_playbook_results

if [ ! -f "${notify_file_path}" ]; then
    echo "No new certificate available."
    exit 0
fi

echo "Running deploy playbook"
deploy_playbook_results=$(ansible-playbook -u ansibleadmin -b "${script_dir}/${PLAYBOOK_DEPLOY_NAME}" 2>&1)
exit_code=$?
echo "${deploy_playbook_results}"

if [ $exit_code != 0 ]; then
    echo "There was an error deploying certificate files!" >&2    
    email_failure "${deploy_playbook_results}"
    exit $exit_code
fi
