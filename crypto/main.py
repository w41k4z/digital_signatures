import os
from crypto_tool import RSAKeyManager
from signer import Signer
import pyfiglet
from colorama import init, Fore

# Enable colorama for Windows
init(autoreset=True)

def print_banner():
  banner = pyfiglet.figlet_format("Crypto CLI")
  print(Fore.CYAN + banner)

def print_menu():
  print(Fore.YELLOW + "Please choose an option:")
  print("1 - Generate RSA keys")
  print("2 - Sign document")
  print("3 - Exit\n")


def main():
  manager = RSAKeyManager()
  signer = Signer()

  while True:
    os.system("clear" if os.name != "nt" else "cls")
    print_banner()
    print_menu()

    choice = input(Fore.GREEN + "Enter your choice: ").strip()

    if choice == "1":
      username = input(Fore.CYAN + "Enter username for key generation: ").strip()
      if not username:
        print(Fore.RED + "Username cannot be empty.")
        input("Press Enter to continue...")
        continue
      manager.generate_keys_for_user(username)
      print(Fore.GREEN + f"Keys generated successfully for user '{username}'.")
      input("Press Enter to continue...")
    
    elif choice == "2":
      username = input(Fore.CYAN + "Enter username: ").strip()
      file_path = input(Fore.CYAN + "Enter path to .txt file to sign: ").strip()
      try:
        signer.sign_document(username, file_path)
      except Exception as e:
          print(Fore.RED + f"Error: {str(e)}")
      input("Press Enter to continue...")

    elif choice == "3":
      print(Fore.BLUE + "Goodbye!")
      break
    else:
      print(Fore.RED + "Invalid choice. Try again.")
      input("Press Enter to continue...")

if __name__ == "__main__":
  main()
