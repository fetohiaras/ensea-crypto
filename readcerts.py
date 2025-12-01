import argparse
import socket
import ssl
import hashlib
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False
from urllib.request import urlopen, Request
from urllib.parse import urlparse

#!/usr/bin/env python3

def format_name(name):
    # name is a tuple of tuples returned by SSLSocket.getpeercert()
    parts = []
    for rdn in name:
        for attr, value in rdn:
            parts.append(f"{attr}={value}")
    return ", ".join(parts)

def hex_fingerprint(data, algo='sha256'):
    h = hashlib.new(algo, data).hexdigest().upper()
    return ":".join(h[i:i+2] for i in range(0, len(h), 2))

def fetch_cert(host, port, timeout=5):
    ctx = ssl.create_default_context()
    # allow fetching certificates even if they don't validate
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            info = ssock.getpeercert()
            return der, info

def main():
    p = argparse.ArgumentParser(description="Curl a URL, retrieve SSL cert and print info")
    p.add_argument("url", help="URL to fetch (e.g. https://example.com/path)")
    args = p.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        print("Only http/https URLs are supported.")
        return

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # perform a simple GET (no verification to avoid errors for self-signed)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = Request(args.url, headers={"User-Agent": "curl-python/1.0"})
        with urlopen(req, context=ctx, timeout=10) as resp:
            body = resp.read(1024)  # read first 1KB
            print(f"HTTP {resp.status} {resp.reason} - read {len(body)} bytes (showing up to 1KB)\n")
            print(body.decode(errors="replace"))
            print("\n" + "="*60 + "\n")
    except Exception as e:
        print(f"Warning: failed to fetch URL content: {e}\n")

    # only attempt cert retrieval for TLS
    if parsed.scheme != "https":
        print("No SSL certificate for non-HTTPS URL.")
        return

    try:
        der, info = fetch_cert(host, port)
    except Exception as e:
        print(f"Failed to retrieve certificate from {host}:{port} - {e}")
        return

    print(f"Certificate information for {host}:{port}\n")
    # (debug output removed)

    # Prefer cryptography parsing for subject/issuer/validity and key details
    pub_alg = None
    pub_details = ""
    sig_alg = None
    if _HAS_CRYPTO:
        try:
            cert = x509.load_der_x509_certificate(der)
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            # Use UTC-safe attributes when available to avoid CryptographyDeprecationWarning
            nb = getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", None)
            na = getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None)
            not_before = nb.isoformat() if nb is not None else "N/A"
            not_after = na.isoformat() if na is not None else "N/A"

            # public key details
            pubkey = cert.public_key()
            if isinstance(pubkey, rsa.RSAPublicKey):
                pub_alg = "RSA"
                pub_details = f"key size: {pubkey.key_size} bits"
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                pub_alg = "EC"
                try:
                    pub_details = f"curve: {pubkey.curve.name}"
                except Exception:
                    pub_details = "curve: unknown"
            elif isinstance(pubkey, dsa.DSAPublicKey):
                pub_alg = "DSA"
                pub_details = f"key size: {pubkey.key_size} bits"
            else:
                pub_alg = type(pubkey).__name__

            # signature algorithm
            try:
                sig_oid = cert.signature_algorithm_oid.dotted_string
                sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm is not None else None
                sig_alg = f"OID={sig_oid}" + (f", hash={sig_hash}" if sig_hash else "")
            except Exception:
                sig_alg = "unknown"
        except Exception:
            subject = format_name(info.get("subject", ()))
            issuer = format_name(info.get("issuer", ()))
            not_before = info.get("notBefore", "N/A")
            not_after = info.get("notAfter", "N/A")
    else:
        subject = format_name(info.get("subject", ()))
        issuer = format_name(info.get("issuer", ()))
        not_before = info.get("notBefore", "N/A")
        not_after = info.get("notAfter", "N/A")

    # Print requested fields
    print(f"Subject: {subject}")
    print(f"Emitter:  {issuer}")
    print(f"Validity period (Not Before / Not After): {not_before} -> {not_after}")
    print(f"Fingerprint (SHA1):   {hex_fingerprint(der, 'sha1')}")
    print(f"Fingerprint (SHA256): {hex_fingerprint(der, 'sha256')}")

    # Try to extract public key algorithm and signature algorithm using cryptography
    if _HAS_CRYPTO:
        try:
            cert = x509.load_der_x509_certificate(der)
            pubkey = cert.public_key()
            pub_alg = "unknown"
            pub_details = ""
            if isinstance(pubkey, rsa.RSAPublicKey):
                pub_alg = "RSA"
                pub_details = f"key size: {pubkey.key_size} bits"
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                pub_alg = "EC"
                try:
                    pub_details = f"curve: {pubkey.curve.name}"
                except Exception:
                    pub_details = "curve: unknown"
            elif isinstance(pubkey, dsa.DSAPublicKey):
                pub_alg = "DSA"
                pub_details = f"key size: {pubkey.key_size} bits"
            else:
                pub_alg = type(pubkey).__name__

            sig_alg = None
            try:
                # signature_algorithm_oid and signature_hash_algorithm provide details
                sig_oid = cert.signature_algorithm_oid.dotted_string
                sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm is not None else None
                sig_alg = f"OID={sig_oid}" + (f", hash={sig_hash}" if sig_hash else "")
            except Exception:
                sig_alg = "unknown"

            print(f"Public key and associated algorithm: {pub_alg} ({pub_details})")
            print(f"Signature algorithm: {sig_alg}")
        except Exception as e:
            print(f"(cryptography) Failed to parse certificate details: {e}")
    else:
        print("Public key and associated algorithm: (requires 'cryptography' package)")
        print("Signature algorithm: (requires 'cryptography' package)")
    # print PEM (first lines) for convenience
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        pem_lines = pem.strip().splitlines()
        print("\nPEM (first 8 lines):")
        for line in pem_lines[:8]:
            print(line)
    except Exception:
        pass

if __name__ == "__main__":
    main()