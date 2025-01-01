#!/usr/bin/python

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from ansible.module_utils.basic import AnsibleModule
import os
import sys


def cert_content_match(path, content):
    if not os.path.isfile(path):
        return False

    exist_cert = None
    with open(path, 'rb') as cert_file:
        exist_cert_content = cert_file.read()
    exist_cert = x509.load_pem_x509_certificate(exist_cert_content)
    del exist_cert_content

    new_cert = x509.load_pem_x509_certificate(content)

    if new_cert.fingerprint(hashes.SHA256()) == exist_cert.fingerprint(hashes.SHA256()):
        print("They are equal")
        return True
    else:
        return False


def split_certificate_chain(src, dest_dir):
    """
    Splits a certificate chain file into individual certificate files.
    Each certificate is saved as a separate file in the destination directory.
    """
    if not os.path.isfile(src):
        raise Exception(f"Source file '{src}' does not exist.")

    if not os.path.isdir(dest_dir):
        raise Exception(f"Destination directory '{dest_dir}' does not exist.")

    # tmp_dir = "/tmp/split_letsencrypt_chain"
    # if not os.path.isdir(tmp_dir):
    #     try:
    #         os.makedirs(tmp_dir)
    #     except OSError as err:
    #         return False, f"Failed to create temporary directory: {err}"

    try:
        with open(src, 'rb') as chain_file:
            chain_content = chain_file.read()
    except Exception as err:
        raise Exception(f"Error opening file '{src}' for reading: {err}")

    certificates = chain_content.split(b"-----END CERTIFICATE-----")

    certs_created = []
    changed = False
    for i, cert in enumerate(certificates):
        if not cert.startswith(b"-----BEGIN CERTIFICATE-----"):
            continue

        cert_content = cert + b"-----END CERTIFICATE-----\n"
        try:
            cert_pem = x509.load_pem_x509_certificate(cert_content)
        except Exception as err:
            raise Exception(
                f"Error parsing file '{src}': {err}")
        del cert_pem

        padded_num = str(i).zfill(2)
        cert_file_path = os.path.join(
            dest_dir, f"chain_{padded_num}.pem")

        if not cert_content_match(cert_file_path, cert_content):
            # if os.path.isfile(cert_file_path):
            #     os.remove(cert_file_path)
            with open(cert_file_path, 'wb') as cert_file:
                cert_file.write(cert_content)
            changed = True

        certs_created.append(cert_file_path)

    return changed, certs_created


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
    # src = "/opt/certificates/live/letsencrypt/sd87.bc.ca/chain.pem"
    # dest_dir = "/opt/certificates/live/letsencrypt/sd87.bc.ca"

    result = dict(
        changed=False,
        message="",
        chain_files=[]
    )

    if module.check_mode:
        result['message'] = "Check mode: no changes made."
        module.exit_json(**result)

    chain_files = []
    has_changed = False
    try:
        has_changed, chain_list = split_certificate_chain(src, dest_dir)
        chain_files += chain_list
    except Exception as err:
        module.fail_json(msg=err)

    result["changed"] = has_changed
    result["chain_files"] = chain_files

    if has_changed:
        result["message"] = f"Split '{src}' into multiple chain files."
    else:
        result["message"] = f"Separate chain files already exist for {src}."

    module.exit_json(**result)


if __name__ == '__main__':
    main()
