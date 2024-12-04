1.	Write a program to perform encryption and decryption using Caesar cipher (substitutional cipher).

def caesar_cipher_encrypt(text, shift):
    """
    Encrypt the text using Caesar cipher.
    :param text: The plaintext to encrypt
    :param shift: The shift value for encryption
    :return: Encrypted text
    """
    result = ""
    for char in text:
        if char.isalpha():  # Process only alphabetic characters
            ascii_base = ord('A') if char.isupper() else ord('a')
            # Calculate new character after shift
            result += chr((ord(char) - ascii_base + shift) % 26 + ascii_base)
        else:
            result += char  # Non-alphabetic characters remain unchanged
    return result


def caesar_cipher_decrypt(text, shift):
    """
    Decrypt the text using Caesar cipher.
    :param text: The encrypted text
    :param shift: The shift value used during encryption
    :return: Decrypted text
    """
    return caesar_cipher_encrypt(text, -shift)  # Decrypt by reversing the shift

def main():
    """
    Main function to run encryption and decryption
    """
    print("Caesar Cipher Program")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    
    choice = input("Enter your choice (1 or 2): ")
    
    if choice not in ['1', '2']:
        print("Invalid choice. Please run the program again.")
        return

    message = input("Enter the message: ")
    shift = int(input("Enter the shift value (1-25): ")) % 26  # Normalize shift value

    if choice == '1':  # Encryption
        encrypted_message = caesar_cipher_encrypt(message, shift)
        print(f"\nEncrypted message: {encrypted_message}")
    elif choice == '2':  # Decryption
        decrypted_message = caesar_cipher_decrypt(message, shift)
        print(f"\nDecrypted message: {decrypted_message}")


if __name__ == "__main__":
    main()








2. Write a program to perform encryption and decryption using Rail Fence Cipher
(transpositional cipher)

def rail_fence_encrypt(text, key):
    """
    Encrypt the text using Rail Fence Cipher.
    :param text: The plaintext to encrypt
    :param key: The number of rails (depth of encryption)
    :return: Encrypted text
    """
    # Create a 2D list to simulate the zigzag rail pattern
    rail = [['' for _ in range(len(text))] for _ in range(key)]
    direction_down = False  # Direction toggle
    row, col = 0, 0

    for char in text:
        rail[row][col] = char
        col += 1

        # Change direction at the top or bottom rail
        if row == 0 or row == key - 1:
            direction_down = not direction_down

        # Move up or down the rails
        row += 1 if direction_down else -1

    # Concatenate characters row-wise to get the encrypted text
    encrypted_text = ''.join([''.join(row) for row in rail])
    return encrypted_text


def rail_fence_decrypt(text, key):
    """
    Decrypt the text using Rail Fence Cipher.
    :param text: The encrypted text
    :param key: The number of rails (depth of encryption)
    :return: Decrypted text
    """
    # Create a 2D list to simulate the zigzag rail pattern
    rail = [['' for _ in range(len(text))] for _ in range(key)]
    direction_down = None
    row, col = 0, 0

    # Mark the rails that are used
    for _ in text:
        rail[row][col] = '*'
        col += 1

        if row == 0:
            direction_down = True
        elif row == key - 1:
            direction_down = False

        row += 1 if direction_down else -1

    # Fill the marked rails with the encrypted text
    index = 0
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] == '*' and index < len(text):
                rail[i][j] = text[index]
                index += 1

    # Read the text in a zigzag pattern
    result = []
    row, col = 0, 0
    for _ in text:
        result.append(rail[row][col])
        col += 1

        if row == 0:
            direction_down = True
        elif row == key - 1:
            direction_down = False

        row += 1 if direction_down else -1

    return ''.join(result)

def main():
    """
    Main function to run encryption and decryption
    """
    print("Rail Fence Cipher Program")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    
    choice = input("Enter your choice (1 or 2): ")
    
    if choice not in ['1', '2']:
        print("Invalid choice. Please run the program again.")
        return

    message = input("Enter the message: ").replace(" ", "")  # Remove spaces for simplicity
    key = int(input("Enter the number of rails (key): "))

    if choice == '1':  # Encryption
        encrypted_message = rail_fence_encrypt(message, key)
        print(f"\nEncrypted message: {encrypted_message}")
    elif choice == '2':  # Decryption
        decrypted_message = rail_fence_decrypt(message, key)
        print(f"\nDecrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()












3. Write a Python program that defines a function and takes a password string as input and
returns its SHA-256 hashed representation as a hexadecimal string.


import hashlib

def hash_password(password):
    """
    Hash a password using SHA-256.
    :param password: The password string to hash
    :return: The SHA-256 hashed representation as a hexadecimal string
    """
    # Encode the password to bytes
    password_bytes = password.encode('utf-8')
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()
    # Update the hash object with the password bytes
    sha256_hash.update(password_bytes)
    # Return the hexadecimal representation of the hash
    return sha256_hash.hexdigest()


def main():
    """
    Main function to demonstrate password hashing.
    """
    # Prompt user for a password
    password = input("Enter the password to hash: ")
    # Hash the password using SHA-256
    hashed_password = hash_password(password)
    # Display the hashed representation
    print(f"SHA-256 Hashed Password: {hashed_password}")


if __name__ == "__main__":
    main()










5. Write a Python program that generates a password using a random combination of
words from a dictionary file.


import random


def load_dictionary(file_path):
    """
    Load words from a dictionary file into a list.
    :param file_path: Path to the dictionary file
    :return: List of words
    """
    try:
        with open(file_path, 'r') as file:
            words = [line.strip() for line in file if line.strip()]
        return words
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []


def generate_password(word_list, num_words=4):
    """
    Generate a password using random words from the word list.
    :param word_list: List of words
    :param num_words: Number of words to include in the password
    :return: Generated password
    """
    if len(word_list) < num_words:
        raise ValueError("Not enough words in the list to generate a password.")
    return ''.join(random.choice(word_list) for _ in range(num_words))


def main():
    """
    Main function to generate a random password.
    """
    file_path = input("Enter the path to the dictionary file: ")
    word_list = load_dictionary(file_path)

    if not word_list:
        return

    try:
        num_words = int(input("Enter the number of words to include in the password: "))
        if num_words <= 0:
            print("The number of words must be greater than 0.")
            return
        password = generate_password(word_list, num_words)
        print(f"\nGenerated Password: {password}")
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()











6. Write a Python program that simulates a brute-force attack on a password by trying out
all possible character combinations.


import itertools
import string
import time

def brute_force(password, max_length=4):
    """
    Simulate a brute-force attack to guess the password.
    :param password: The target password to guess
    :param max_length: Maximum length of the password to attempt
    :return: The guessed password, number of attempts, and the time taken
    """
    start_time = time.time()
    characters = string.ascii_letters + string.digits + string.punctuation
    attempts = 0  # Counter for the number of attempts

    # Try all combinations of characters up to the maximum length
    for length in range(1, max_length + 1):
        for guess in itertools.product(characters, repeat=length):
            attempts += 1
            guess_password = ''.join(guess)
            if guess_password == password:
                end_time = time.time()
                return guess_password, attempts, end_time - start_time

    return None, attempts, time.time() - start_time


def main():
    """
    Main function to demonstrate a brute-force attack simulation.
    """
    password = input("Enter the password to brute-force: ")
    max_length = int(input("Enter the maximum password length to attempt: "))

    guessed_password, attempts, time_taken = brute_force(password, max_length)

    if guessed_password:
        print(f"\nPassword guessed: {guessed_password}")
        print(f"Number of attempts: {attempts}")
        print(f"Time taken: {time_taken:.2f} seconds")
    else:
        print("\nPassword not found within the maximum length.")
        print(f"Number of attempts: {attempts}")
        print(f"Time taken: {time_taken:.2f} seconds")


if __name__ == "__main__":
    main()
