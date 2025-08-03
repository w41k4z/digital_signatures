import os
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


signature_metadata = {
  "user": "w41k4z",
  "timestamp": "2025-08-03T17:33:29.848139+00:00",
  "signature": "fr6KM+DmqFhmiC9h42Tr0R+hc2Hyus1e+hjms5bxooTairuF+XAYUtJw6rV3b+2i1JnoKsb6N5bcHjiEZ+2Zb4two5PjzY1nzN4R+BMxQ9/r0tkMFv4qWFK4I+z9MDzLxI9iIdpjU4RnBJEY9erHpuOBbq74WMkZn1ljRN/2MjaAXI4vIZvgCxxCpI24LkrfNQCkTzRra4xiuHybbI3y7ojBkWQsD/bkl06C49cf5zRjElns6cdzCuoXvGboYsR9vSw40MgzwCPjZrdRCR45JHZRjy77D6UkWoRO9NxfmrpQ4y7mxbV2ofimPZ/uvnDEf3LyvGxQI+WRYubnnWv/HA=="
}

public_key_path = "./users/w41k4z/w41k4z_public.pem"
with open(public_key_path, "rb") as key_file:
  public_key = serialization.load_pem_public_key(key_file.read())

file_path = "./users/w41k4z/files/test.txt"
with open(file_path, "rb") as f:
  file_data = f.read()

digest = hashes.Hash(hashes.SHA256())
digest.update(file_data)
file_hash = digest.finalize()

signature = base64.b64decode(signature_metadata["signature"])

try:
  public_key.verify(
    signature,
    file_hash,
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )
  print("✅ Signature is valid.")
  print("✅ File has not been tampered (hash matches).")
except InvalidSignature:
  print("❌ Invalid signature! File may be forged.")
except Exception:
  print("❌ Invalid signature!")
