#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as cert_serialization
import hashlib
import os
import sys


def cert_content_match(path, new_cert):
    if not os.path.isfile(path):
        return False

    exist_cert = None
    with open(path, 'rb') as cert_file:
        exist_cert_content = cert_file.read()
    exist_cert = x509.load_pem_x509_certificate(exist_cert_content)
    del exist_cert_content

    if new_cert.fingerprint(hashes.SHA256()) == exist_cert.fingerprint(hashes.SHA256()):
        return True
    else:
        return False

def is_chain_match(path, new_chain_certs):
    if not os.path.isfile(path):
        return False

    exist_chain_certs = []
    with open(path, 'rb') as chain_file:
        chain_content = chain_file.read()

    exist_chain_pem = chain_content.split(b"-----END CERTIFICATE-----")
    for i, cert_pem in enumerate(exist_chain_pem):
        if not cert_pem.startswith(b"-----BEGIN CERTIFICATE-----"):
            continue

        cert_content = cert_pem + b"-----END CERTIFICATE-----\n"
        try:
            cert = x509.load_pem_x509_certificate(cert_content)
        except Exception as err:
            raise Exception(
                f"Error parsing file '{src}': {err}")
        exist_chain_certs.append(cert)
    del chain_content
    del exist_chain_pem

    # print(f"lenght of new_chain_certs -> {str(len(new_chain_certs))}, length of exist_chain_certs -> {str(len(exist_chain_certs))}")
    if len(new_chain_certs) != len(exist_chain_certs):
        del exist_chain_certs
        return False

    for i, new_cert in enumerate(new_chain_certs):
        new_cert_hash = new_cert.fingerprint(hashes.SHA256())
        exist_cert_hash = exist_chain_certs[i].fingerprint(hashes.SHA256())
        if new_cert_hash != exist_cert_hash:
            del new_cert_hash
            del exist_cert_hash
            del exist_chain_certs
            return False
        del new_cert_hash
        del exist_cert_hash

    del exist_chain_certs
    return True

def is_root_or_sub_ca(certificate):
    try:
        # Extract the basicConstraints extension
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value

        # Check if it's a CA certificate
        if not basic_constraints.ca:
            return False  # Not a CA certificate

        return True
    except x509.ExtensionNotFound:
        # If the basicConstraints extension is missing, it's not a CA
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

    try:
        with open(src, 'rb') as chain_file:
            chain_content = chain_file.read()
    except Exception as err:
        raise Exception(f"Error opening file '{src}' for reading: {err}")

    chain_certs_created = []
    client_cert = None
    chain_certs = []
    changed = False
    certificates = []
    for i, cert_pem in enumerate(chain_content.split(b"-----END CERTIFICATE-----")):
        cert_pem_trim = cert_pem.lstrip(b"\n")
        while cert_pem_trim.startswith(b'\n'):
            cert_pem_trim = cert_pem_trim.lstrip(b'\n')

        if not cert_pem_trim.startswith(b"-----BEGIN CERTIFICATE-----"):
            continue

        cert_content = cert_pem_trim + b"-----END CERTIFICATE-----\n"
        try:
           cert = x509.load_pem_x509_certificate(cert_content)
        except Exception as err:
            raise Exception(
                f"Error parsing file '{src}': {err}")

        if is_root_or_sub_ca(cert):
            if len(chain_certs) < 1:
                chain_certs.append(cert)
            else:
                tmp_list = []
                added = False
                for item in chain_certs:
                    if item.issuer == cert.subject:
                        tmp_list.append(cert)
                        tmp_list.append(item)
                        added = True
                if not added:
                    tmp_list.append(cert)
                chain_certs = tmp_list
        else:
            client_cert = cert


    chain_path = os.path.join(
        dest_dir,
        "chain.pem"
    )
    if not is_chain_match(chain_path, chain_certs):
        with open(chain_path, 'wb') as chain_file:
            for i, chain_cert in enumerate(chain_certs):
                chain_file.write(
                    chain_cert.public_bytes(encoding=cert_serialization.Encoding.PEM)
                )
                chain_file.write(b"\n")
        chain_certs_created.append(chain_path)
        changed = True

    for i, chain_cert in enumerate(chain_certs):
        padded_num = str(i).zfill(2)
        cert_file_path = os.path.join(
            dest_dir,
            f"chain_{padded_num}.pem"
        )
        del padded_num

        cert_content = chain_cert.public_bytes(encoding=cert_serialization.Encoding.PEM)
        if not cert_content_match(cert_file_path, chain_cert):
            with open(cert_file_path, 'wb') as cert_file:
                cert_file.write(cert_content)
            changed = True
        del cert_content

        chain_certs_created.append(cert_file_path)
        del cert_file_path

    client_cert_path = os.path.join(
        dest_dir,
        "cert.pem"
    )
    if not cert_content_match(client_cert_path, client_cert):
        with open(client_cert_path, 'wb') as cert_file:
            cert_file.write(
                client_cert.public_bytes(encoding=cert_serialization.Encoding.PEM)
            )
        changed = True

    return changed, chain_certs_created, client_cert_path


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
    # src = "/opt/certificates/live/letsencrypt/wan.centennialchristian.ca/fullchain.pem"
    # dest_dir = "/opt/certificates/live/letsencrypt/wan.centennialchristian.ca"

    result = dict(
        changed=False,
        message="",
        chain_files=[]
    )

    if module.check_mode:
        result['message'] = "Check mode: no changes made."
        module.exit_json(**result)

    client_file = None
    chain_files = []
    has_changed = False
    try:
        has_changed, chain_list, client_file = split_certificate_chain(src, dest_dir)
        chain_files += chain_list
    except Exception as err:
        module.fail_json(msg=err)
    # has_changed, chain_list, client_file = split_certificate_chain(src, dest_dir)
    # chain_files += chain_list

    result["changed"] = has_changed
    result["chain_files"] = chain_files
    result["client_file"] = client_file

    if has_changed:
        result["message"] = f"Split '{src}' into multiple chain files and/or a client certificate."
    else:
        result["message"] = f"Separate chain files and/or a client certificate already exist for {src}."

    module.exit_json(**result)
    # print(result)
    # sys.exit()


if __name__ == '__main__':
    main()
