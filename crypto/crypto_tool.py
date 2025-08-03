import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class RSAKeyManager:

  def __init__(self, base_dir = "users"):
    self.base_dir = base_dir
    os.makedirs(self.base_dir, exist_ok=True)

  def generate_keys_for_user(self, username: str):
    user_dir = os.path.join(self.base_dir, username)
    os.makedirs(user_dir, exist_ok=True)

    private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048
    )
    public_key = private_key.public_key()

    private_key_path = os.path.join(user_dir, f"{username}_private.pem")
    public_key_path = os.path.join(user_dir, f"{username}_public.pem")

    with open(private_key_path, "wb") as priv_file:
      priv_file.write(
        private_key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=serialization.NoEncryption()
        )
      )

    with open(public_key_path, "wb") as pub_file:
      pub_file.write(
        public_key.public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
      )
