To encrypt a Pandas DataFrame and then save it to a Parquet file, you can follow these steps:

Encrypt the DataFrame.
Save the encrypted DataFrame to a Parquet file.
Decrypt it back when needed.
Complete Example with Pandas DataFrame and Parquet
Here’s how you can accomplish this:

python
Copy code
import base64
import os
import pandas as pd
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Function to derive a key from a password and salt
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Function to encrypt a DataFrame
def encrypt_dataframe(password: str, df: pd.DataFrame) -> tuple:
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key_from_password(password, salt)
    cipher = Fernet(key)

    # Encrypt each string value in the DataFrame
    encrypted_df = df.applymap(lambda x: cipher.encrypt(str(x).encode()) if isinstance(x, str) else x)
    
    return salt, encrypted_df

# Function to decrypt a DataFrame
def decrypt_dataframe(password: str, salt: bytes, encrypted_df: pd.DataFrame) -> pd.DataFrame:
    key = derive_key_from_password(password, salt)
    cipher = Fernet(key)

    # Decrypt each value in the DataFrame
    decrypted_df = encrypted_df.applymap(lambda x: cipher.decrypt(x).decode() if isinstance(x, bytes) else x)
    
    return decrypted_df

# Function to save the encrypted DataFrame to a Parquet file
def save_to_parquet(salt: bytes, encrypted_df: pd.DataFrame, filename: str):
    # Convert the salt to a hex string to store with the DataFrame
    salt_hex = salt.hex()
    
    # Create a DataFrame with the salt included as a separate row/column
    # Optionally, you could save it as a separate file
    encrypted_df['Salt'] = salt_hex
    encrypted_df.to_parquet(filename, index=False)

# Function to read the encrypted DataFrame from a Parquet file
def read_from_parquet(filename: str) -> tuple:
    encrypted_df = pd.read_parquet(filename)
    # Extract the salt from the last row/column
    salt_hex = encrypted_df.pop('Salt').iloc[0]
    salt = bytes.fromhex(salt_hex)
    return salt, encrypted_df

# Example Usage
if __name__ == "__main__":
    # Create a sample DataFrame
    data = {'Name': ['Alice', 'Bob', 'Charlie'], 'Secret': ['12345', '67890', 'abcde']}
    df = pd.DataFrame(data)

    print("Original DataFrame:")
    print(df)

    password = "my_secure_password"  # Set your password

    # Encrypt the DataFrame
    salt, encrypted_df = encrypt_dataframe(password, df)

    # Save the encrypted DataFrame to a Parquet file
    parquet_filename = "encrypted_data.parquet"
    save_to_parquet(salt, encrypted_df, parquet_filename)
    print(f"\nEncrypted DataFrame saved to {parquet_filename}")

    # Read the encrypted DataFrame from the Parquet file
    salt, encrypted_df_read = read_from_parquet(parquet_filename)

    # Decrypt the DataFrame
    decrypted_df = decrypt_dataframe(password, salt, encrypted_df_read)
    print("\nDecrypted DataFrame:")
    print(decrypted_df)
Explanation of the Code:
Key Derivation:

The function derive_key_from_password is used to generate a key from the password and salt.
Encryption:

The encrypt_dataframe function encrypts all string values in the DataFrame.
Decryption:

The decrypt_dataframe function decrypts the encrypted values in the DataFrame.
Saving to Parquet:

The save_to_parquet function saves the encrypted DataFrame along with the salt to a Parquet file. It converts the salt to a hexadecimal string before saving it to ensure it's stored in a suitable format.
Reading from Parquet:

The read_from_parquet function reads the Parquet file and retrieves the salt used for encryption. The salt is converted back from its hexadecimal string representation.
Example Usage:

The main block creates a sample DataFrame, encrypts it, saves it to a Parquet file, reads it back, and decrypts it to show the final result.
