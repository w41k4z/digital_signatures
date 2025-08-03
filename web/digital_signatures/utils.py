
import os
import json
import base64
from django.conf import settings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from django.contrib.auth.hashers import make_password, check_password
from cryptography.hazmat.primitives.serialization import load_pem_public_key

REGISTER_FILE = os.path.join(settings.BASE_DIR, 'register.json')

def load_ca_keys():
  """Load CA's own key pair"""
  with open(os.path.join(settings.BASE_DIR, 'ca_private.pem'), 'rb') as f:
      ca_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
      )
  with open(os.path.join(settings.BASE_DIR, 'ca_public.pem'), 'rb') as f:
      ca_public_key = serialization.load_pem_public_key(f.read())
  return ca_private_key, ca_public_key

def load_register():
  try:
    with open(REGISTER_FILE, 'r') as f:
      return json.load(f)
  except (FileNotFoundError, json.JSONDecodeError):
    return {}
    
def save_register(data):
  with open(REGISTER_FILE, 'w') as f:
    json.dump(data, f)

def create_ca_signature(username, public_key_content):
  """Create CA signature for a user's public key"""
  ca_private_key, _ = load_ca_keys()
  data_to_hash = f"{username}{public_key_content}".encode('utf-8')
  digest = hashes.Hash(hashes.SHA256())
  digest.update(data_to_hash)
  hash_value = digest.finalize()

  return ca_private_key.sign(
    hash_value,
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )  

def register_user(username, password, public_key):
  register_data = load_register()
  
  if username in register_data:
    return False, "Username already exists"
  
  try:
    public_key_content = public_key.read().decode('utf-8')
    if not public_key_content.startswith('-----BEGIN PUBLIC KEY-----'):
      return False, "Invalid public key format"
        
    ca_signature = create_ca_signature(username, public_key_content)
    register_data[username] = {
      'public_key': public_key_content,
      'password': make_password(password),
      'CA_signature': base64.b64encode(ca_signature).decode('utf-8')
    }
    save_register(register_data)
    return True, "Registration successful"
      
  except Exception as e:
    return False, f"Error processing registration: {str(e)}"


def authenticate_user(username, password):
  register_data = load_register()
  if username in register_data:
    return check_password(password, register_data[username]['password'])
  return False

def get_unsigned_files():
  files_dir = os.path.join(settings.BASE_DIR, 'files')
  unsigned_files = []
  
  for root, dirs, files in os.walk(files_dir):
    for file in files:
      if file.endswith('.txt'):
        file_path = os.path.join(root, file)
        signature_path = os.path.join(root, f"{os.path.splitext(file)[0]}.signature.json")
        if not os.path.exists(signature_path):
          unsigned_files.append({
            'name': file,
            'path': file_path,
            'folder': os.path.basename(root)
          })
  return unsigned_files

def get_signed_files():
  files_dir = os.path.join(settings.BASE_DIR, 'files')
  signed_files = []
  
  for root, dirs, files in os.walk(files_dir):
    for file in files:
      if file.endswith('.signature.json'):
        txt_file = file.replace('.signature.json', '.txt')
        if os.path.exists(os.path.join(root, txt_file)):
          with open(os.path.join(root, file), 'r') as f:
            try:
              sig_data = json.load(f)
              signed_files.append({
                'name': txt_file,
                'user': sig_data.get('user', 'Unknown'),
                'timestamp': sig_data.get('timestamp', ''),
                'folder': os.path.basename(root)
              })
            except json.JSONDecodeError:
              continue
  return signed_files

def verify_user(username):
  try:
    # Get user's public key
    register_data = load_register()
    user_data = register_data.get(username)

    data_to_verify = f"{username}{user_data['public_key']}".encode('utf-8')
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data_to_verify)
    hash_value = digest.finalize()

    # Verify signature
    _, ca_public_key = load_ca_keys()
    ca_public_key.verify(
      base64.b64decode(user_data['CA_signature']),
      hash_value,
      padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
      ),
      hashes.SHA256()
    )
    return True, ""
  except Exception as e:
    return False, f"Verification failed: {str(e)}"

def verify_signature(username, file_path, signature_file):
  try:
    user_is_valid = verify_user(username)
    if not user_is_valid:
      return False, f"Verification failed for the user: {username}" 

    # Load signature data
    sig_data = json.load(signature_file)
    signature = base64.b64decode(sig_data['signature'])
    
    # Get user's public key
    register_data = load_register()
    public_key_pem = register_data[username]['public_key']
    public_key = load_pem_public_key(public_key_pem.encode())
    
    # Calculate file hash
    with open(file_path, 'rb') as f:
      file_content = f.read()
    file_hash = hashes.Hash(hashes.SHA256())
    file_hash.update(file_content)
    digest = file_hash.finalize()
    
    # Verify signature
    public_key.verify(
      signature,
      digest,
      padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
      ),
      hashes.SHA256()
    )
    
    # Save signature file
    file_dir = os.path.dirname(file_path)
    signature_filename = f"{os.path.splitext(os.path.basename(file_path))[0]}.signature.json"
    signature_path = os.path.join(file_dir, signature_filename)
    
    with open(signature_path, 'w') as f:
        json.dump(sig_data, f)
        
    return True, "Signature verified and stored"
      
  except Exception as e:
    return False, f"Signature verification failed: {str(e)}"
