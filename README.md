# Text Encrypter 🔐

This project demonstrates **password-based text encryption and decryption** using Python and the `cryptography` library. It uses `Fernet` encryption, with a key derived from a password and salt via PBKDF2.

## Features

- 🔑 Password-based encryption
- 🧂 Salted key derivation using PBKDF2HMAC
- 🔒 Secure encryption/decryption using Fernet
- 📁 Easily extendable to work with files or user input

## Installation

Make sure you have Python 3.x installed.

Install the required library:

```bash
pip install cryptography
```

## Usage

1. Clone the repository or copy the notebook.
2. Run the notebook in Jupyter or any compatible environment (e.g., VS Code, PyCharm).
3. Change the `password`, `salt`, and `message` variables as needed.
4. Run the cells to encrypt and decrypt the message.

## Example

```python
password = "mysecurepassword"
salt = os.urandom(16)
message = "Hello, this is a secret message!"

# Generates a key from password
key = generate_key(password, salt)

# Encrypts the message
token = encrypt_message(message, key)

# Decrypts the token
original_message = decrypt_message(token, key)
```

## Security Note

- Always store your **salt** securely along with the ciphertext.
- Never hardcode sensitive passwords in production code.

## License

This project is licensed under the MIT License.
