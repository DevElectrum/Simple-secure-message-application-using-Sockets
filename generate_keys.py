from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


KEY_DIR = Path("keys")


def generate_rsa_key_pair():
    """Create one RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, path):
    """Save a private key in PEM format without a password."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def save_public_key(public_key, path):
    """Save a public key in PEM format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def generate_and_save_keys(name):
    private_key, public_key = generate_rsa_key_pair()

    save_private_key(private_key, KEY_DIR / f"{name}_private.pem")
    save_public_key(public_key, KEY_DIR / f"{name}_public.pem")


def main():
    KEY_DIR.mkdir(exist_ok=True)

    generate_and_save_keys("server")
    generate_and_save_keys("client")

    print("Generated RSA keys in the keys/ folder.")


if __name__ == "__main__":
    main()
