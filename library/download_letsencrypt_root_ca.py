#!/usr/bin/python

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from ansible.module_utils.basic import AnsibleModule
import os
import requests
import sys


def get_ca(cert: x509.Certificate):
    aia_extension = cert.extensions.get_extension_for_oid(
        x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
    )
    ca_issuers_url = None
    for access_description in aia_extension.value:
        if access_description.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
            ca_issuers_url = access_description.access_location.value

    del aia_extension
    if ca_issuers_url is None:
        raise Exception(
            f"The CA_ISSUERS missing from Authority Information Access extension for '{cert.subject.rfc4514_string()}'."
        )
    try:
        http_res = requests.get(ca_issuers_url)
        if not http_res.ok:
            http_res.raise_for_status()
    except Exception as err:
        raise Exception(f"Error connecting to url '{ca_issuers_url}': {err}")

    ca_certs = []
    ca_cert = None
    try:
        ca_cert = x509.load_der_x509_certificate(http_res.content)
    except Exception as err:
        try:
            ca_cert = x509.load_pem_x509_certificate(http_res.content)
        except Exception as err:
            raise Exception(
                f"Content from URL '{http_res.url}' derived from CA Issuers property of the Authority Information Access extension of certficate with subject '{cert.subject.rfc4514_string()}' does not contain a DER or PEM encoded certificate"
            )
    ca_certs.append(ca_cert)
    if ca_cert.issuer != ca_cert.subject:
        ca_certs.extend(get_ca(ca_cert))

    return ca_certs


def download_ca(src, dest_dir):
    """
    Checks the certificate for the CA Issuers URL property inside the Authority
    Information Access extension and uses that to download the root certificate
    authority certificate.
    """
    if not os.path.isfile(src):
        raise Exception(f"Source file '{src}' does not exist.")

    if not os.path.isdir(dest_dir):
        raise Exception(f"Destination directory '{dest_dir}' does not exist.")

    try:
        with open(src, 'rb') as chain_file:
            chain_content = chain_file.read()
    except Exception as err:
        raise Exception(f"Error opening file '{src}' for reading: {err}")

    certificates = chain_content.split(b"-----END CERTIFICATE-----")
    top_cert = None
    for i, cert_bytes in enumerate(certificates):
        if not cert_bytes.startswith(b"-----BEGIN CERTIFICATE-----"):
            continue

        cert_content = cert_bytes + b"-----END CERTIFICATE-----\n"
        try:
            cert = x509.load_pem_x509_certificate(cert_content)
        except Exception as err:
            raise Exception(
                f"Error parsing certificate PEM file '{src}': {err}")
        del cert_content

        if top_cert is None:
            top_cert = cert
        if top_cert.issuer == cert.subject:
            top_cert = cert

    ca_certs = get_ca(top_cert)
    del top_cert

    has_changed = False
    ca_results = []
    for i, ca_cert in enumerate(ca_certs):
        if (i + 1) == len(ca_certs):
            ca_path = os.path.join(dest_dir, "rootca.pem")
        else:
            padded_num = str(i).zfill(2)
            ca_path = os.path.join(dest_dir, f"intermediate_{padded_num}.pem")

        ca_results.append({
            "end_date": ca_cert.not_valid_after.strftime(
                "%Y-%m-%d %H:%M:%S %Z%z"
            ),
            "issuer": ca_cert.issuer.rfc4514_string(),
            "md5_fingerprint": ':'.join(
                f"{byte:02x}" for byte in ca_cert.fingerprint(hashes.MD5())
            ),
            "path": ca_path,
            "serial_number": ca_cert.serial_number,
            "subject": ca_cert.subject.rfc4514_string(),
            "start_date": ca_cert.not_valid_before.strftime(
                "%Y-%m-%d %H:%M:%S %Z%z"
            )
        })

        write_ca_file = True
        if os.path.isfile(ca_path):
            exist_cert_bytes = None
            try:
                with open(ca_path, "rb") as exist_ca_file:
                    exist_cert_bytes = exist_ca_file.read()
            except Exception as err:
                raise Exception(
                    f"Error reading existing file '{ca_path}': {err}"
                )
            exist_cert = x509.load_pem_x509_certificate(exist_cert_bytes)
            del exist_cert_bytes
            if exist_cert.fingerprint(hashes.MD5()) == ca_cert.fingerprint(hashes.MD5()):
                write_ca_file = False
            del exist_cert

        if write_ca_file:
            has_changed = True
            pem_bytes = ca_cert.public_bytes(
                encoding=serialization.Encoding.PEM
            )
            with open(ca_path, "wb") as ca_file:
                ca_file.write(pem_bytes)

    return has_changed, ca_results


def main():
    module_args = dict(
        src=dict(
            type='str',
            required=True
        ),
        dest_dir=dict(
            type='str',
            required=True
        ),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    src = module.params['src']
    dest_dir = module.params['dest_dir']
    # src = "/opt/certificates/live/letsencrypt/wan.centennialchristian.ca/chain.pem"
    # dest_dir = "/opt/certificates/live/letsencrypt/wan.centennialchristian.ca"

    result = dict(
        changed=False,
        message="",
        items=[]
    )

    if module.check_mode:
        result['message'] = "Check mode: no changes made."
        module.exit_json(**result)

    has_changed = False
    ca_items = []
    try:
        has_changed, ca_items = download_ca(src, dest_dir)
    except Exception as err:
        module.fail_json(msg=f"{err}")

    result["changed"] = has_changed
    result["items"].extend(ca_items)

    if has_changed:
        if len(ca_items) == 1:
            result["message"] = "Downloaded root certificate authority certificate."
        else:
            result["message"] = "Download intermediate certificates and root certificate authority certificate."
    else:
        result["message"] = "Intermediate and/or root certificate authority certificates already downloaded."

    module.exit_json(**result)


if __name__ == '__main__':
    main()
