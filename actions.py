"""
Certificate actions.
"""

import pathlib
import subprocess


def create_root_ca(root_ca_name, root_ca_key_password):
    outpath = pathlib.Path(f"{root_ca_name}.key").absolute()
    if outpath.exists():
        raise FileExistsError("[-] That keyfile already exists!  Cancelling keyfile creation.")

    command = ["openssl", "genrsa", "-aes256", "-out", str(outpath), "4096"]
    subprocess.check_call(command)
    raise NotImplementedError()
    # openssl genrsa -aes256 -out ca.key 4096                     # produces ca.key
    # openssl req -new -x509 -days 365 -key ca.key -out ca.crt    # produces ca.crt


def verify_keyfile_password(keyfile_filepath, keyfile_password) -> bool:
    command = ["openssl", "rsa", "-in", str(keyfile_filepath), "-passin", "stdin"]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc.communicate(input=keyfile_password.encode("utf-8"))
    out = proc.poll()
    return not bool(out)
