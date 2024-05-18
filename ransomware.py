"""
------------------------------------------------------------
This code is created by VeilWr4ith.

DO NOT USE THIS SCRIPT FOR ILLEGAL PURPOSES! THE AUTHOR WILL NOT BE HELD RESPONSIBLE IF YOU ENGAGE IN ILLEGAL ACTIVITIES USING THIS CODE!
------------------------------------------------------------
"""

import pathlib
import secrets
import os
import base64
import getpass
import json
import time
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def generate_salt(size=16):
    """Generate the salt used for key derivation,
    size is the length of the salt to generate"""
    return secrets.token_bytes(size)


def derive_key(salt, password):
    """Derive the key from the password using the passed salt"""
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    return kdf.derive(password.encode())


def load_salt():
    # load salt from salt.salt file
    return open(".salt.salt", "rb").read()


def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    """Generates a key from a password and the salt.
    If load_existing_salt is True, it'll load the salt from a file
    in the current directory called ".salt.salt".
    If .save_salt is True, then it will generate a new salt
    and save it to ".salt.salt" """
    if load_existing_salt:
        # load existing salt
        salt = load_salt()
    elif save_salt:
        # generate new salt and save it
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)


def encrypt(filename, key):
    """Given a filename (str) and key (bytes), it encrypts the file and writes it"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def encrypt_folder(foldername, key):
    # if it's a folder, encrypt the entire folder (i.e all the containing files)
    for child in pathlib.Path(foldername).glob("*"):
        try:
            if child.is_file():
                print(f"[*] Encrypting {child}... Be prepared for irreversible transformations.")
                # encrypt the file
                encrypt(child, key)
            elif child.is_dir():
                # if it's a folder, encrypt the entire folder by calling this function recursively
                encrypt_folder(child, key)
        except PermissionError:
            pass


def decrypt(filename, key):
    """Given a filename (str) and key (bytes), it decrypts the file and writes it"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Decrypting this file might unleash chaos... Think twice.")
        return
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    # Check if expiration time has passed
    expiration_time = load_timer()
    if expiration_time and time.time() > expiration_time:
        print("Timer expired. Deleting timer file.")
        os.remove("timer.json")


def decrypt_folder(foldername, key):
    # if it's a folder, decrypt the entire folder
    for child in pathlib.Path(foldername).glob("*"):
        try:
            if child.is_file():
                print(f"[*] Decrypting {child}... The darkness within shall reveal itself.")
                # decrypt the file
                decrypt(child, key)
            elif child.is_dir():
                decrypt_folder(child, key)
        except PermissionError:
            pass


def start_timer(expiration_time):
    """Starts the timer."""
    with open("timer.json", "w") as timer_file:
        json.dump({"expiration_time": expiration_time}, timer_file)


def load_timer():
    """Loads the expiration time from the timer file."""
    try:
        with open("timer.json", "r") as timer_file:
            timer_data = json.load(timer_file)
            return timer_data["expiration_time"]
    except FileNotFoundError:
        return None


def save_timer(expiration_time):
    """Saves the expiration time to the timer file."""
    with open(".timer.json", "w") as timer_file:
        json.dump({"expiration_time": expiration_time}, timer_file)


def delete_encrypted_files(directory):
    """Deletes all files within the specified directory."""
    for child in pathlib.Path(directory).rglob("*"):
        if child.is_file():
            try:
                decrypt(child, key)
                os.remove(child)
            except cryptography.fernet.InvalidToken:
                # If decryption fails, it means the file was not encrypted, so skip it
                pass
            except PermissionError:
                # If permission denied error occurs, skip deleting the file
                pass


def print_time_left(expiration_time):
    """Prints the time left until expiration."""
    current_time = time.time()
    time_left = expiration_time - current_time
    if time_left <= 0:
        print("Time has already expired.")
    else:
        print(f"Time left until expiration: {int(time_left)} seconds.")


def encrypt_and_schedule_deletion(path, key, timer):
    """Encrypts the files and schedules deletion after timer expires."""
    if os.path.isfile(path):
        # if it is a file, encrypt it
        encrypt(path, key)
        expiration_time = time.time() + timer
        start_timer(expiration_time)
        print_time_left(expiration_time)
    elif os.path.isdir(path):
        encrypt_folder(path, key)
        expiration_time = time.time() + timer
        start_timer(expiration_time)
        print_time_left(expiration_time)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="File Encryptor Script with a Password")
    parser.add_argument("path", help="Path to encrypt/decrypt, can be a file or an entire folder")
    parser.add_argument("-s", "--salt-size", help="If this is set, a new salt with the passed size is generated",
                        type=int)
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Whether to encrypt the file/folder, only -e or -d can be specified.")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Whether to decrypt the file/folder, only -e or -d can be specified.")
    parser.add_argument("-t", "--timer", type=int, help="Expiration time for encryption in seconds")
    # Parse the arguments
    args = parser.parse_args()
    # Get the password
    if args.encrypt:
        password = getpass.getpass("Enter the password for encryption: ")
    elif args.decrypt:
        password = getpass.getpass("Enter the password you used for encryption: ")
    # Generate the key
    if args.salt_size:
        key = generate_key(password, salt_size=args.salt_size, save_salt=True)
    else:
        key = generate_key(password, load_existing_salt=True)

    # Get the flags
    encrypt_ = args.encrypt
    decrypt_ = args.decrypt
    if encrypt_ and decrypt_:
        raise TypeError("Invoking both encryption and decryption simultaneously... A dangerous game.")
    elif encrypt_:
        encrypt_and_schedule_deletion(args.path, key, args.timer)
    elif decrypt_:
        if os.path.isfile(args.path):
            expiration_time = load_timer()
            if expiration_time and time.time() > expiration_time:
                print("Timer expired. Deleting encrypted files.")
                delete_encrypted_files(os.path.dirname(args.path))
            else:
                decrypt(args.path, key)
        elif os.path.isdir(args.path):
            expiration_time = load_timer()
            if expiration_time and time.time() > expiration_time:
                print("Timer expired. Deleting encrypted files.")
                delete_encrypted_files(args.path)
            else:
                decrypt_folder(args.path, key)
    else:
        raise TypeError(
            "Your indecisiveness can lead to unforeseen consequences. Please specify your action: encrypt or decrypt?")

