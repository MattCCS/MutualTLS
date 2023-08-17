"""
Certificate actions.
"""

import pathlib
import subprocess
from typing import Optional


def generate_key(entity_name: str) -> pathlib.Path:
    """
    Generate a key.
    """
    # openssl genrsa -aes256 -out ca.key 4096
    # (produces ca.key)
    outpath = pathlib.Path(f"{entity_name}.key").absolute()

    print(f"[ ] Checking for path collisions...")
    if outpath.exists():
        raise FileExistsError("[-] That keyfile already exists!  Cancelling keyfile creation.")

    print(f"[ ] Generating keyfile...")
    command = ["openssl", "genrsa", "-aes256", "-out", str(outpath), "4096"]
    subprocess.check_call(command)
    print(f"[+] Created {outpath.name} at {str(outpath)}.")

    return outpath


def create_root_ca_certificate(
    root_ca_name: Optional[str]=None,
    root_ca_keyfile: Optional[str]=None,
) -> pathlib.Path:
    """
    Create a self-signed (root) certificate.
    """
    # openssl req -new -x509 -days 365 -key ca.key -out ca.crt
    # (produces ca.crt)
    if not any([root_ca_name, root_ca_keyfile]):
        raise ValueError("Must provide root_ca_name or root_ca_keyfile!")

    if root_ca_keyfile:
        keypath = pathlib.Path(root_ca_keyfile).absolute()
    else:
        keypath = pathlib.Path(f"{root_ca_name}.key").absolute()

    outpath = keypath.with_suffix(".crt")

    print(f"[ ] Checking for path collisions...")
    if not keypath.exists():
        raise FileNotFoundError("[-] No keyfile found!  Cancelling certificate creation.")
    if outpath.exists():
        raise FileExistsError("[-] Certificate already exists!  Cancelling certificate creation.")

    print(f"[ ] Generating certificate...")
    command = [
        "openssl", "req", "-new", "-x509",
        "-days", "365",
        "-key", str(keypath),
        "-out", str(outpath),
    ]
    subprocess.check_call(command)
    print(f"[+] Created {outpath.name} at {str(outpath)}.")
    print(f"[+] View your certificate details with: `systemssl x509 -in {outpath} -text -noout`")

    return outpath


def generate_csr(entity_name: Optional[str]=None, entity_keyfile: Optional[str]=None) -> pathlib.Path:
    """
    Generate a Certificate Signing Request.
    """
    # openssl req -new -key client.key -subj "/CN=client CSR" -out client.csr
    # (produces client.csr)
    if not any([entity_name, entity_keyfile]):
        raise ValueError("Must provide entity_name or entity_keyfile!")

    if entity_keyfile:
        keypath = pathlib.Path(entity_keyfile).absolute()
    else:
        keypath = pathlib.Path(f"{entity_name}.key").absolute()

    outpath = keypath.with_suffix(".csr")

    print(f"[ ] Checking for path collisions...")
    if outpath.exists():
        raise FileExistsError("[-] .csr file already exists!  Cancelling .csr creation.")

    print(f"[ ] Generating CSR...")
    command = [
        "openssl", "req", "-new",
        "-key", str(keypath),
        "-subj", f"/CN={keypath.stem} CSR",
        "-out", str(outpath),
    ]
    subprocess.check_call(command)
    print(f"[+] Created {outpath.name} at {str(outpath)}.")

    return outpath


def sign_csr(
    client_name: Optional[str]=None,
    client_csr: Optional[pathlib.Path]=None,
    ca_name: Optional[str]=None,
    ca_certificate: Optional[pathlib.Path]=None,
    ca_keyfile: Optional[pathlib.Path]=None,
) -> pathlib.Path:
    """
    Sign a Certificate Signing Request, producing a certificate.
    """
    # openssl x509 -req -days 365 -sha256 -in client.csr -CA ca.crt \
    #     -CAkey ca.key -set_serial 01 -out client.crt
    # (produces client.crt)
    if not any([client_name, client_csr]):
        raise ValueError("Must provide client_name or client_csr!")

    if not (ca_name or all([ca_certificate, ca_keyfile])):
        raise ValueError("Must provide ca_name or (ca_certificate and ca_keyfile)!")

    if client_csr:
        csrpath = pathlib.Path(client_csr).absolute()
    else:
        csrpath = pathlib.Path(f"{client_name}.csr").absolute()

    outpath = csrpath.with_suffix(".crt")

    if not ca_name:
        ca_certificate = pathlib.Path(ca_certificate).absolute()
        ca_keyfile = pathlib.Path(ca_keyfile).absolute()
    else:
        ca_certificate = pathlib.Path(f"{ca_name}.crt").absolute()
        ca_keyfile = pathlib.Path(f"{ca_name}.key").absolute()

    print(f"[ ] Checking for required files...")
    if not csrpath.exists():
        raise FileNotFoundError("[-] No CSR found!  Cancelling certificate creation.")
    if not ca_certificate.exists():
        raise FileNotFoundError("[-] No CA certificate found!  Cancelling certificate creation.")
    if not ca_keyfile.exists():
        raise FileNotFoundError("[-] No CA key found!  Cancelling certificate creation.")

    print(f"[ ] Checking for path collisions...")
    if outpath.exists():
        raise FileExistsError("[-] Certificate already exists!  Cancelling certificate creation.")

    print(f"[ ] Generating certificate from CSR...")
    command = [
        "openssl", "x509", "-req",
        "-days", "365",  # TODO: parameterize
        "-sha256",
        "-in", str(csrpath),
        "-CA", str(ca_certificate),
        "-CAkey", str(ca_keyfile),
        "-set_serial", "01",  # TODO: parameterize
        "-out", str(outpath),
    ]
    subprocess.check_call(command)
    print(f"[+] Created {outpath.name} at {str(outpath)}.")

    return outpath


def convert_crt_to_p12(
    client_name: Optional[str]=None,
    client_certificate: Optional[pathlib.Path]=None,
    client_keyfile: Optional[pathlib.Path]=None,
) -> pathlib.Path:
    """
    Combine a certificate and key into a .p12 file.
    """
    # openssl pkcs12 -export -clcerts -inkey client.key \
    #   -in client.crt -out client.p12 \
    #   -name "client Cert p12"
    # (produces client.p12)
    if not (client_name or all([client_certificate, client_keyfile])):
        raise ValueError("Must provide client_name or (client_certificate and client_keyfile)!")

    if not client_name:
        client_certificate = pathlib.Path(client_certificate).absolute()
        client_keyfile = pathlib.Path(client_keyfile).absolute()
    else:
        client_certificate = pathlib.Path(f"{client_name}.crt").absolute()
        client_keyfile = pathlib.Path(f"{client_name}.key").absolute()

    outpath = client_certificate.with_suffix(".p12")

    print(f"[ ] Checking for path collisions...")
    if outpath.exists():
        raise FileExistsError("[-] .p12 file already exists!  Cancelling .p12 creation.")

    print(f"[ ] Generating .p12 for client...")
    command = [
        "openssl", "pkcs12", "-export", "-clcerts",
        "-inkey", str(client_keyfile),
        "-in", str(client_certificate),
        "-out", str(outpath),
        "-name", f"{client_certificate.stem} Cert p12",
    ]
    subprocess.check_call(command)
    print(f"[+] Created {outpath.name} at {str(outpath)}.")

    return outpath


def verify_keyfile_password(keyfile_filepath, keyfile_password) -> bool:
    """
    Verify that the given password decrypts the given keyfile.
    """
    command = ["openssl", "rsa", "-in", str(keyfile_filepath), "-passin", "stdin"]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc.communicate(input=keyfile_password.encode("utf-8"))
    out = proc.poll()
    return not bool(out)
