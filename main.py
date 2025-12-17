import json
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)
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

# Password generator function (optional)
def generate_password(length):
     """
    Generate a random strong password of the specified length.

    Args:
        length (int): The desired length of the password.

    Returns:
        str: A random strong password.
    """
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

    
# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []

SHIFT = 5

# Function to add a new password 
def add_password():
    """
    Add a new password to the password manager.

    This function should prompt the user for the website, username,  and password and store them to lits with same index. Optionally, it should check password strengh with the function is_strong_password. It may also include an option for the user to
    generate a random strong password by calling the generate_password function.

    Returns:
        None
    """
    website = input("Enter website name: ")
    username = input("Enter username: ")

    generate = input("Do you want to generate a random strong password? (y/n): ").lower()

    if generate == 'y':
        length = input("Enter desired password length (minimum 8): ")
        try:
            length = int(length)
            password = generate_password(length)
            print(f"Generated password: {password}")
        except ValueError:
            print("Invalid length. Using default length of 12.")
            password = generate_password(12)
            print(f"Generated password: {password}")
    else:
        password = input("Enter password: ")

        #tsekataan salasanan vahvuus
         if not is_strong_password(password):
            print("Warning: This password is weak!")
            print("A strong password should:")
            print("- Be at least 8 characters long")
            print("- Contain uppercase and lowercase letters")
            print("- Contain at least one digit")
            print("- Contain at least one special character")
            proceed = input("Do you want to continue with this password? (y/n): ").lower()
            if proceed != 'y':
                print("Password not added.")
                return
    encrypted_password = caesar_encrypt(password, SHIFT)
    
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted_password)
    
    print(f"Password for {website} added successfully!")


# Function to retrieve a password 
def get_password():
    """
    Retrieve a password for a given website.

    This function should prompt the user for the website name and
    then display the username and decrypted password for that website.

    Returns:
        None
    """
    website = input("Enter website name: ")
    
    if website in websites:
        index = websites.index(website)
        username = usernames[index]
        encrypted_password = encrypted_passwords[index]
        
        # Decrypt the password
        decrypted_password = caesar_decrypt(encrypted_password, SHIFT)
        
        print(f"\nWebsite: {website}")
        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
    else:
        print(f"No password found for {website}")


# Function to save passwords to a JSON file 
def save_passwords():
 """
    Save the password vault to a file.

    This function should save passwords, websites, and usernames to a text
    file named "vault.txt" in a structured format.

    Returns:
        None
    """
    vault_data = {
        'websites': websites,
        'usernames': usernames,
        'encrypted_passwords': encrypted_passwords
    }
    
    try:
        # Save to JSON file for structured format
        with open('vault.txt', 'w') as file:
            json.dump(vault_data, file, indent=4)
        print("Passwords saved successfully to vault.txt!")
    except Exception as e:
        print(f"Error saving passwords: {e}")



# Function to load passwords from a JSON file 
def load_passwords():
     """
    Load passwords from a file into the password vault.

    This function should load passwords, websites, and usernames from a text
    file named "vault.txt" (or a more generic name) and populate the respective lists.

    Returns:
        None
     """
    global encrypted_passwords, websites, usernames
    
    try:
        with open('vault.txt', 'r') as file:
            vault_data = json.load(file)
            
            # Populate the global lists
            websites = vault_data.get('websites', [])
            usernames = vault_data.get('usernames', [])
            encrypted_passwords = vault_data.get('encrypted_passwords', [])
            
        print(f"Loaded {len(websites)} password(s) successfully!")
    except FileNotFoundError:
        print("No vault file found. Starting with empty vault.")
    except json.JSONDecodeError:
        print("Error: Vault file is corrupted.")
    except Exception as e:
        print(f"Error loading passwords: {e}")

  # Main method
def main():
# implement user interface 

  while True:
    print("\nPassword Manager Menu:")
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
        passwords = load_passwords()
        print("Passwords loaded successfully!")
    elif choice == "5":
        break
    else:
        print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()




