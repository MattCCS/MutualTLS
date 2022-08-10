#!/usr/bin/env python

"""
CLI to run tools related to certs and mutual TLS.
"""

import argparse
import getpass
import pathlib
import secrets
import sys

import tabcompletion

import actions


__author__ = "matthewcotton.cs@gmail.com"


def create_root_ca():
    root_ca_name = input("Root CA name: ")
    root_ca_key_password = secrets.token_hex()
    return actions.create_root_ca(
        root_ca_name=root_ca_name,
        root_ca_key_password=root_ca_key_password,
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
    subparsers = parser.add_subparsers(dest="action")

    parser_crc = subparsers.add_parser("create-root-ca")

    parser_vkp = subparsers.add_parser("verify-keyfile-password")
    parser_vkp.add_argument("-k", "--keyfile_filepath", required=True)

    tabcompletion.register(parser)
    tabcompletion.register(parser_vkp)
    return parser.parse_args()


def main():
    args = parse_args()
    action = args.action

    if action == "create-root-ca":
        create_root_ca()
    elif action == "verify-keyfile-password":
        valid = verify_keyfile_password(pathlib.Path(args.keyfile_filepath))
        print("[+] Password was valid." if valid else "[-] Password was invalid.")
        sys.exit(int(not valid))
    else:
        raise NotImplementedError()


if __name__ == '__main__':
    main()
