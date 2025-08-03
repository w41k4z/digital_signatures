# signer.py
import os
import json
import base64
import shutil
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

class Signer:
  def __init__(self, users_dir="users"):
    self.users_dir = users_dir

  def sign_document(self, username: str, file_path: str):
    user_dir = os.path.join(self.users_dir, username)
    private_key_path = os.path.join(user_dir, f"{username}_private.pem")

    if not os.path.isdir(user_dir):
      raise FileNotFoundError(f"User '{username}' not found.")
    if not os.path.isfile(private_key_path):
      raise FileNotFoundError(f"Private key for user '{username}' not found.")
    if not os.path.isfile(file_path) or not file_path.endswith(".txt"):
      raise ValueError("File must be a valid .txt file.")

    # Load private key
    with open(private_key_path, "rb") as f:
      private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
      )

    # Read file contents and compute SHA-256 hash
    with open(file_path, "rb") as f:
      content = f.read()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(content)
    file_hash = digest.finalize()

    # Sign the hash
    signature = private_key.sign(
      file_hash,
      padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
      ),
      hashes.SHA256()
    )

    # Output directory
    files_dir = os.path.join(user_dir, "files")
    os.makedirs(files_dir, exist_ok=True)

    base_filename = os.path.basename(file_path).rsplit('.', 1)[0]

    # Save .sig file
    with open(os.path.join(files_dir, f"{base_filename}.sig"), "wb") as sig_file:
      sig_file.write(signature)

    # Save .signature.json
    metadata = {
      "user": username,
      "timestamp": datetime.now(timezone.utc).isoformat(),
      "signature": base64.b64encode(signature).decode("utf-8")
    }

    with open(os.path.join(files_dir, f"{base_filename}.signature.json"), "w", encoding="utf-8") as json_file:
      json.dump(metadata, json_file, indent=4)
    
    copied_txt_path = os.path.join(files_dir, os.path.basename(file_path))
    shutil.copy2(file_path, copied_txt_path)

    print(f"File '{file_path}' signed successfully.")
