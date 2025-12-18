import json
import re
import random
import string

# Caesar cipher encryption and decryption functions
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False
    return True

def generate_password(length):
    if length < 8:
        length = 8

    password_chars = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]

    all_chars = string.ascii_letters + string.digits + string.punctuation
    password_chars += [random.choice(all_chars) for _ in range(length - 4)]
    random.shuffle(password_chars)
    
    return ''.join(password_chars)

# Globaalit listat tietojen tallennukseen
encrypted_passwords = []
websites = []
usernames = []

SHIFT = 5

def add_password():
    website = input("Enter website name: ")
    username = input("Enter username: ")
    generate = input("Do you want to generate a random strong password? (y/n): ").lower()

    if generate == 'y':
        length_input = input("Enter desired password length (minimum 8): ")
        try:
            length = int(length_input)
            password = generate_password(length)
        except ValueError:
            print("Invalid length. Using default length of 12.")
            password = generate_password(12)
        print(f"Generated password: {password}")
    else:
        password = input("Enter password: ")
        if not is_strong_password(password):
            print("Warning: This password is weak!")
            print("- Be at least 8 characters long\n- Use upper/lowercase, digits and special chars.")
            proceed = input("Do you want to continue anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Password not added.")
                return

    encrypted_password = caesar_encrypt(password, SHIFT)
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted_password)
    print(f"Password for {website} added successfully!")

def get_password():
    website = input("Enter website name: ")
    if website in websites:
        index = websites.index(website)
        username = usernames[index]
        encrypted_password = encrypted_passwords[index]
        decrypted_password = caesar_decrypt(encrypted_password, SHIFT)
        
        print(f"\nWebsite: {website}")
        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
    else:
        print(f"No password found for {website}")

def save_passwords():
    vault_data = {
        'websites': websites,
        'usernames': usernames,
        'encrypted_passwords': encrypted_passwords
    }
    try:
        with open('vault.txt', 'w') as file:
            json.dump(vault_data, file, indent=4)
        print("Passwords saved successfully to vault.txt!")
    except Exception as e:
        print(f"Error saving passwords: {e}")

def load_passwords():
    global encrypted_passwords, websites, usernames
    try:
        with open('vault.txt', 'r') as file:
            vault_data = json.load(file)
            websites[:] = vault_data.get('websites', [])
            usernames[:] = vault_data.get('usernames', [])
            encrypted_passwords[:] = vault_data.get('encrypted_passwords', [])
        print(f"Loaded {len(websites)} password(s) successfully!")
    except FileNotFoundError:
        print("No vault file found. Starting with empty vault.")
    except Exception as e:
        print(f"Error loading passwords: {e}")

def main():
    while True:
        print("\n--- Password Manager ---")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Load Passwords")
        print("5. Quit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
