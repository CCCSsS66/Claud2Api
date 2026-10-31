#!/usr/bin/env python3
"""Create a self-signed TLS certificate for direct public deployment."""
import argparse
import ipaddress
import os
import pathlib
import subprocess
import sys


def label(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return f"IP:{host}"
    except ValueError:
        return f"DNS:{host}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="directory for tls-cert.pem and tls-key.pem")
    parser.add_argument(
        "--host",
        action="append",
        default=[],
        help="DNS name or IP for the certificate SAN (repeatable; defaults to localhost and 127.0.0.1)",
    )
    parser.add_argument("--days", type=int, default=825)
    args = parser.parse_args()
    hosts = args.host or ["localhost", "127.0.0.1"]
    directory = pathlib.Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    cert = directory / "tls-cert.pem"
    key = directory / "tls-key.pem"
    if cert.exists() or key.exists():
        return print("refusing to overwrite an existing certificate", file=sys.stderr) or 1
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            str(args.days),
            "-subj",
            f"/CN={hosts[0]}",
            "-addext",
            "subjectAltName=" + ",".join(label(host) for host in hosts),
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
    )
    os.chmod(key, 0o600)
    print(f"certificate: {cert}")
    print(f"private key: {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
