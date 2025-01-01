#!/usr/bin/python

import logging
from ansible.module_utils.basic import AnsibleModule
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes as ssl_hashes
from cryptography.hazmat.primitives.serialization import pkcs12
import os
import re
import sys
import xml.etree.ElementTree as ET

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)


# return cert.fingerprint(hashes.MD5()).hex()

def get_pan_xml_status(text):
    response_xml = ET.fromstring(text)
    message_element = response_xml.find(".//message")
    msg_element = response_xml.find(".//msg")
    if message_element is not None:
        lines = message_element.findall(".//line")
        if lines is not None:
            msg = ""
            for line in lines:
                msg += f" {line.text}"
        else:
            msg = message_element.text
    elif msg_element is not None:
        lines = msg_element.findall(".//line")
        if lines is not None:
            msg = ""
            for line in lines:
                msg += f" {line.text}"
        else:
            msg = msg_element.text
    else:
        msg = None
    status = response_xml.get("status")
    code = response_xml.get("code")

    return status, msg, code


def get_pan_xml_pubkey(text):
    response_xml = ET.fromstring(text)
    pubkey_el = response_xml.find(".//public-key")
    if pubkey_el is not None:
        return pubkey_el.text.encode()
    else:
        raise Exception("XML does not contain the public-key tag")


def get_existing_cert(ip_address, api_key, cert_name, template):
    if template is None:
        url = (
            f"https://{ip_address}/api/?key={api_key}&type=export"
            f"&category=certificate&certificate-name={cert_name}&format=pem"
            f"&include-key=no"
        )
    else:
        url = (
            f"https://{ip_address}/api/?key={api_key}&type=config&action=get"
            f"&xpath=/config/devices/entry[@name='localhost.localdomain']"
            f"/template/entry[@name='{template}']"
            f"/config/shared/certificate/entry[@name='{cert_name}']"
        )
    response = requests.get(url, verify=False)

    pan_code, pan_msg, pan_status = None, None, None
    if "<response " in response.text:
        pan_status, pan_msg, pan_code = get_pan_xml_status(response.text)

    if response.status_code == 200 and pan_status is None:
        return x509.load_pem_x509_certificate(response.content)
    if "<public-key" in response.text:
        cert_data = None
        try:
            cert_data = get_pan_xml_pubkey(response.text)
        except Exception as err:
            raise Exception(f"PaloAlto API error: {err}")
        return x509.load_pem_x509_certificate(cert_data)
    elif pan_code == "7" or "Failed to prepare certificate" in pan_msg:
        # there is no existing certificate with that name
        return None
    elif pan_msg is not None:
        raise Exception(pan_msg)
    elif pan_code is not None:
        raise Exception(f"Error code={pan_code}.")
    else:
        raise Exception(
            f"HTTP Error with PaloAlto API (status code {response.status_code}): {response.reason}"
        )


def get_new_cert(cert_path, cert_format, passphrase):
    file_content = None
    with open(cert_path, "rb") as new_cert_file:
        file_content = new_cert_file.read()

    cert = None
    if cert_format == "pkcs12":
        if passphrase is None:
            raise Exception(
                f"If the cert_format is pkcs12 then passphrase is required."
            )
        else:
            bpassphrase = passphrase.encode("utf-8")

        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
            file_content,
            bpassphrase
        )
        del additional_certs
        del private_key
    elif cert_format == "pem":
        if b"--BEGIN CERTIFICATE--" not in file_content:
            raise Exception(
                "Cert format PEM specified, however certificate is not PEM format.")

        certificates = []
        for block in file_content.split(b"-----END CERTIFICATE-----"):
            if b"CERTIFICATE" in block:
                certificates.append(x509.load_pem_x509_certificate(
                    block + b"-----END CERTIFICATE-----\n"
                ))

        for i in range(2):
            for cert_item in certificates:
                if cert is None:
                    cert = cert_item
                if cert_item.issuer == cert.subject:
                    cert = cert_item

    elif cert_format == "der":
        cert = x509.load_der_x509_certificate(file_content)
    else:
        raise Exception(f"Unsupported format {cert_format}")

    return cert


def import_certificate(ip_address, api_key, cert_name, cert_format, cert_path, cert_mode, passphrase, template):

    params = {
        'type': 'import',
        'certificate-name': cert_name,
        'format': cert_format,
        'key': api_key
    }
    params["category"] = cert_mode

    if passphrase is not None:
        params['passphrase'] = passphrase

    if template:
        params["target-tpl"] = template

    url = f"https://{ip_address}/api/"
    files = {'file': open(cert_path, "rb")}

    response = None
    try:
        response = requests.post(url, data=params, files=files, verify=False)
    except Exception as err:
        raise Exception(f"HTTP request error on import API: {err}")

    print(response.text)
    pan_status, pan_msg, pan_code = None, None, None
    if response.text:
        pan_status, pan_msg, pan_code = get_pan_xml_status(response.text)
    print(
        f"pan_status -> {pan_status}, pan_code -> {pan_code}, pan_msg -> {pan_msg}"
    )

    if response.status_code == 200 and pan_status == "success":
        if pan_msg:
            return pan_msg
        else:
            return f"Imported certificate with name '{cert_name}'."
    elif pan_msg:
        raise Exception(f"PaloAlto import API error: {pan_msg}")
    else:
        raise Exception("HTTP error on import API. Status Code = {}. Reason = {}.".format(
            response.status_code,
            response.reason
        ))


def main():
    module_args = dict(
        api_key=dict(type='str', required=True, no_log=True),
        format=dict(
            type='str',
            required=True,
            choices=['pem', 'der', 'pkcs12']
        ),
        name=dict(type='str', required=True),
        mode=dict(
            type='str',
            required=False,
            choices=['certificate', 'keypair'],
            default='certificate'
        ),
        ip_address=dict(type='str', required=True),
        passphrase=dict(
            type='str',
            required=False,
            no_log=True,
            default=None
        ),
        path=dict(type='str', required=True),
        template=dict(type='str', required=False, default=None)
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    api_key = module.params['api_key']
    cert_format = module.params['format']
    cert_name = module.params['name']
    cert_path = module.params['path']
    cert_mode = module.params['mode']
    ip_address = module.params['ip_address']
    passphrase = module.params.get('passphrase')
    template = module.params.get('template')
    if template == "None":
        template = None

    # script_name = os.path.basename(os.path.abspath(__file__))
    # log_dir = f"/tmp/{script_name}"
    # print(f"{log_dir}")
    # if not os.path.isdir(log_dir):
    #     os.makedirs(log_dir, exist_ok=True)
    # logging.basicConfig(
    #     filename=f"{log_dir}/debug.{ip_address}.{template}.log",
    #     level=logging.INFO,
    #     format="%(asctime)s [%(levelname)s] %(message)s"
    # )

    if cert_mode == "keypair" and passphrase is None:
        module.fail_json(
            msg="If 'cert_mode' is keypair, 'passphrase' is required."
        )
        # print("If 'cert_mode' is keypair, 'passphrase' is required.")
        # sys.exit()

    exist_cert = None
    try:
        exist_cert = get_existing_cert(
            ip_address,
            api_key,
            cert_name,
            template
        )
    except Exception as err:
        module.fail_json(
            msg=f"Error getting details for cerificate of name {cert_name} on PaloAlto: {err}"
        )

    new_cert = None
    try:
        new_cert = get_new_cert(cert_path, cert_format, passphrase)
    except Exception as err:
        module.fail_json(
            msg=f"Failed to get details of certificate file: {err}"
        )
        # print("Failed to get details of certificate file: {err}")
        # sys.exit()

    result = dict(
        changed=False,
        message=""
    )
    if exist_cert is not None:
        exist_fingerprint = ':'.join(
            f"{byte:02x}" for byte in exist_cert.fingerprint(ssl_hashes.SHA1())
        )
        exist_subject = exist_cert.subject
        exist_issuer = exist_cert.issuer
    else:
        exist_fingerprint = None
        exist_subject = None
        exist_issuer = None

    new_fingerprint = ':'.join(
        f"{byte:02x}" for byte in new_cert.fingerprint(ssl_hashes.SHA1())
    )
    if (
        new_cert.subject == exist_subject
    ) and (
        new_cert.issuer == exist_issuer
    ) and (
        new_fingerprint == exist_fingerprint
    ):
        result["changed"] = False
        result["message"] = f"Certificate name {cert_name} already contains certificate with fingerprint '{new_fingerprint}'."
        module.exit_json(**result)
        # print(result)
        # sys.exit()

    pan_message = None
    try:
        pan_message = import_certificate(
            ip_address,
            api_key,
            cert_name,
            cert_format,
            cert_path,
            cert_mode,
            passphrase,
            template
        )
    except Exception as err:
        module.fail_json(
            msg=f"Failed to import certificate file into PaloAlto: {err}"
        )
        # print("Failed to import certificate file into PaloAlto: {err}")
        # sys.exit()

    result["message"] = pan_message
    result["changed"] = True
    module.exit_json(**result)
    # print(result)


if __name__ == '__main__':
    main()
