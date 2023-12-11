from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import os
import sqlite3
import secrets
import string

#Create and manage master key
def generate_key_from_password(password, salt):
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key

def create_master_password():
    master_password = input("Set your master password: ")
    salt = os.urandom(32)  # Generate a random salt
    hashed_password = generate_key_from_password(master_password, salt)
    return hashed_password, salt

def login(stored_key, stored_salt):
    entered_password = input("Enter your master password: ")
    entered_key = generate_key_from_password(entered_password, stored_salt)

    if entered_key == stored_key:
        print("Login successful!")
    else:
        print("Login failed. Incorrect master password.")

# Function to generate a random 256-bit AES key
def generate_aes_key():
    return os.urandom(32)

# Function to encrypt data using AES with PKCS#7 padding
def encrypt_data(data, key):
    # Convert data to bytes
    data_bytes = data.encode('utf-8')

    # Calculate the required padding size
    padding_size = 16 - (len(data_bytes) % 16)
    
    # Apply PKCS#7 padding
    padded_data = data_bytes + bytes([padding_size] * padding_size)

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    # Encrypt the padded data
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encode the encrypted data in base64 for storage
    return base64.b64encode(encrypted_data)

# Function to decrypt data using AES with PKCS#7 padding
def decrypt_data(encrypted_data, key):
    # Decode the base64 encoded data
    encrypted_data = base64.b64decode(encrypted_data)

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    
    # Decrypt the data
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove the PKCS#7 padding and decode back to UTF-8
    padding_size = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_size]

    return decrypted_data.decode('utf-8')


#Create and manage DB
def create_database():
    conn = sqlite3.connect("LamtalaaDB.db")
    cursor = conn.cursor()

    # Create a table to store encrypted password entries
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def store_password(website, username, encrypted_password):
    conn = sqlite3.connect("LamtalaaDB.db")
    cursor = conn.cursor()

    # Store the encrypted password in the database
    cursor.execute('''
        INSERT INTO passwords (website, username, encrypted_password)
        VALUES (?, ?, ?)
    ''', (website, username, encrypted_password))

    conn.commit()
    conn.close()

def retrieve_password(website):
    conn = sqlite3.connect("LamtalaaDB.db")
    cursor = conn.cursor()

    # Retrieve the encrypted password from the database based on the website
    cursor.execute('''
        SELECT encrypted_password FROM passwords
        WHERE website = ?
    ''', (website,))

    result = cursor.fetchone()

    conn.close()

    return result[0] if result else None

# Generate a strong, random password with a default length of 12 characters
def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

def main():
    print("Welcome to the Password Manager")

    # Check if the user has set the master password
    stored_key, stored_salt = create_master_password()

    # Generate a random AES key for encryption
    aes_key = generate_aes_key()

    # Create the database and table
    create_database()

    while True:
        print("\nOptions:")
        print("1. Log in")
        print("2. Store password")
        print("3. Retrieve password")
        print("4. Generate strong password")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == "1":
            login(stored_key, stored_salt)
        elif choice == "2":
            website = input("Enter the website: ")
            username = input("Enter the username: ")
            password = input("Enter the password: ")

            # Encrypt the password before storing
            encrypted_password = encrypt_data(password, aes_key)

            # Store the encrypted password in the database
            store_password(website, username, encrypted_password)
            print("Password stored successfully.")
        elif choice == "3":
            website = input("Enter the website: ")

            # Retrieve the encrypted password from the database
            encrypted_password = retrieve_password(website)

            if encrypted_password:
                # Decrypt and display the password
                decrypted_password = decrypt_data(encrypted_password, aes_key)
                print(f"Retrieved password: {decrypted_password}")
            else:
                print("Password not found.")
        elif choice == "4":
            length = int(input("Enter the length of the password: "))

            #Generate strong password
            strong_password = generate_strong_password(length)
            print(f"Strong password: {strong_password}") 
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")


if __name__ == "__main__":
    main()
