"""
Interactive tools related to certificates and mutual TLS.
"""

import argparse
import getpass
import pathlib
import sys
from typing import Optional

import actions


__author__ = "matthewcotton.cs@gmail.com"


def create_root_ca_key(root_ca_name: Optional[str]=None) -> pathlib.Path:
    if root_ca_name is None:
        root_ca_name = input("Root CA name to create key for: ")
    return actions.generate_key(
        entity_name=root_ca_name,
    )


def create_root_ca_certificate(root_ca_name: Optional[str]=None, root_ca_keyfile: Optional[str]=None) -> pathlib.Path:
    if not any([root_ca_name, root_ca_keyfile]):
        root_ca_name = input("Root CA name to create certificate for: ")
    return actions.create_root_ca_certificate(
        root_ca_name=root_ca_name,
        root_ca_keyfile=root_ca_keyfile,
    )


def generate_client_key(client_name=None):
    if client_name is None:
        client_name = input("Client name to create key for: ")
    return actions.generate_key(
        entity_name=client_name,
    )


def generate_client_csr(client_name: Optional[str]=None, client_keyfile: Optional[str]=None) -> pathlib.Path:
    if not any([client_name, client_keyfile]):
        client_name = input("Client name to create certificate for: ")
    return actions.generate_csr(
        entity_name=client_name,
        entity_keyfile=client_keyfile,
    )


def sign_client_certificate(
    client_name: Optional[str]=None,
    client_csr: Optional[pathlib.Path]=None,
    ca_name: Optional[str]=None,
    ca_certificate: Optional[pathlib.Path]=None,
    ca_keyfile: Optional[pathlib.Path]=None,
) -> pathlib.Path:
    if not any([client_name, client_csr]):
        client_name = input("Client name to sign certificate for: ")

    if not (ca_name or all([ca_certificate, ca_keyfile])):
        ca_name = input("CA name who will sign certificate: ")

    return actions.sign_csr(
        client_name=client_name,
        client_csr=client_csr,
        ca_name=ca_name,
        ca_certificate=ca_certificate,
        ca_keyfile=ca_keyfile,
    )


def convert_client_crt_to_p12(
    client_name: Optional[str]=None,
    client_certificate: Optional[str]=None,
    client_keyfile: Optional[str]=None,
) -> pathlib.Path:
    if not (client_name or all([client_certificate, client_keyfile])):
        client_name = input("Client name to create .p12 file for: ")

    return actions.convert_crt_to_p12(
        client_name=client_name,
        client_certificate=client_certificate,
        client_keyfile=client_keyfile,
    )


def verify_keyfile_password(keyfile_filepath) -> bool:
    human_filepath = repr(str(keyfile_filepath.absolute()))
    keyfile_password = getpass.getpass(f"Enter the password for {human_filepath}: ")
    return actions.verify_keyfile_password(
        keyfile_filepath=keyfile_filepath,
        keyfile_password=keyfile_password,
    )


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)

    parser_crc = subparsers.add_parser("create-root-ca")

    parser_gck = subparsers.add_parser("generate-client-key")

    parser_gccsr = subparsers.add_parser("generate-client-csr")

    parser_scc = subparsers.add_parser("sign-client-certificate")

    parser_scc = subparsers.add_parser("convert-client-crt-to-p12")

    parser_vkp = subparsers.add_parser("verify-keyfile-password")
    parser_vkp.add_argument("keyfile_filepath")

    return parser.parse_args()


def main():
    args = parse_args()
    action = args.action

    if action == "create-root-ca":
        root_ca_name = input("Root CA name (spaces optional): ")
        create_root_ca_key(root_ca_name=root_ca_name)
        create_root_ca_certificate(root_ca_name=root_ca_name)
    elif action == "verify-keyfile-password":
        if verify_keyfile_password(pathlib.Path(args.keyfile_filepath)):
            print("[+] Password was correct.")
        else:
            sys.exit("[-] Password was incorrect.")
    elif action == "generate-client-key":
        generate_client_key()
    elif action == "generate-client-csr":
        generate_client_csr()
    elif action == "sign-client-certificate":
        sign_client_certificate()
    elif action == "convert-client-crt-to-p12":
        convert_client_crt_to_p12()
    else:
        raise Exception("Unsupported action.")


if __name__ == "__main__":
    main()
