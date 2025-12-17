import json
import re
import random
import string
import time

def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower() and shifted > ord('z'):
                shifted -= 26
            elif char.isupper() and shifted > ord('Z'):
                shifted -= 26
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
    chars = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]
    all_chars = string.ascii_letters + string.digits + string.punctuation
    chars += [random.choice(all_chars) for _ in range(length - 4)]
    random.shuffle(chars)
    return ''.join(chars)

encrypted_passwords = []
websites = []
usernames = []

SHIFT = 7

def add_password():
    site = input("Syötä sivuston nimi: ")
    user = input("Syötä käyttäjänimi: ")
    gen = input("Haluatko generoida vahvan salasanan? (k/e): ").lower()
    if gen == 'k':
        try:
            length = int(input("Anna haluttu pituus (min 8): "))
        except ValueError:
            length = 12
            print("Virheellinen pituus, käytetään 12 merkkiä.")
        pwd = generate_password(length)
        print(f"Generoitua salasanaa käytetään: {pwd}")
    else:
        pwd = input("Syötä salasana: ")
        if not is_strong_password(pwd):
            print("Varoitus: salasana on heikko!")
            proceed = input("Haluatko silti tallentaa tämän salasanan? (k/e): ").lower()
            if proceed != 'k':
                print("Salasanaa ei lisätty.")
                return
    enc_pwd = caesar_encrypt(pwd, SHIFT)
    websites.append(site)
    usernames.append(user)
    encrypted_passwords.append(enc_pwd)
    print(f"Salasana {site} lisätty onnistuneesti!")
    time.sleep(0.5)

def get_password():
    site = input("Syötä sivuston nimi: ")
    if site in websites:
        i = websites.index(site)
        user = usernames[i]
        pwd = caesar_decrypt(encrypted_passwords[i], SHIFT)
        print(f"\nSivusto: {site}\nKäyttäjä: {user}\nSalasana: {pwd}")
    else:
        print(f"Ei salasanaa sivustolle {site}")

def save_passwords():
    data = {'websites': websites, 'usernames': usernames, 'encrypted_passwords': encrypted_passwords}
    try:
        with open('vault.txt', 'w') as f:
            json.dump(data, f, indent=4)
        print("Salasanat tallennettu vault.txt-tiedostoon.")
    except Exception as e:
        print(f"Tallennus epäonnistui: {e}")

def load_passwords():
    global websites, usernames, encrypted_passwords
    try:
        with open('vault.txt', 'r') as f:
            data = json.load(f)
        websites = data.get('websites', [])
        usernames = data.get('usernames', [])
        encrypted_passwords = data.get('encrypted_passwords', [])
        print(f"Ladattiin {len(websites)} salasanaa onnistuneesti!")
    except FileNotFoundError:
        print("Tiedostoa ei löytynyt, aloitetaan tyhjällä vaultilla.")
    except json.JSONDecodeError:
        print("Virhe vault-tiedostossa!")
    except Exception as e:
        print(f"Lataus epäonnistui: {e}")

def main():
    print("Hei! Tämä on oma password manager -versio.")
    while True:
        print("\nValikko:")
        print("1. Lisää salasana")
        print("2. Hae salasana")
        print("3. Tallenna salasanat")
        print("4. Lataa salasanat")
        print("5. Lopeta")
        choice = input("Valintasi: ")
        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
        elif choice == "5":
            print("Kiitos ohjelman käytöstä!")
            break
        else:
            print("Virheellinen valinta, yritä uudelleen.")

if __name__ == "__main__":
    main()





