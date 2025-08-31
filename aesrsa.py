#AES
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt(plaintext, key, mode):
    # Convert plaintext string to bytes for encryption.
    plaintext_bytes = plaintext.encode('utf-8')

    if mode == "ECB":
        # ECB mode does not use an IV. It requires padding.
        cipher = AES.new(key, AES.MODE_ECB)
        padded_bytes = pad(plaintext_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_bytes)
        return ciphertext

    elif mode == "CBC":
        # CBC mode uses an IV and requires padding.
        cipher = AES.new(key, AES.MODE_CBC)
        padded_bytes = pad(plaintext_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_bytes)
        # Prepend the IV to the ciphertext for transport. This is standard practice.
        return cipher.iv + ciphertext

    elif mode == "CFB":
        # CFB mode acts like a stream cipher, so it does not require padding.
        # It still requires an IV.
        cipher = AES.new(key, AES.MODE_CFB)
        ciphertext = cipher.encrypt(plaintext_bytes)
        # Prepend the IV to the ciphertext.
        return cipher.iv + ciphertext

    else:
        raise ValueError("Unsupported mode. Please choose 'ECB', 'CBC', or 'CFB'.")

def decrypt(encrypted_data, key, mode):

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_padded_bytes = cipher.decrypt(encrypted_data)
        plaintext_bytes = unpad(decrypted_padded_bytes, AES.block_size)
        return plaintext_bytes.decode('utf-8')

    elif mode == "CBC":
        # Extract the IV from the beginning of the data.
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_padded_bytes = cipher.decrypt(ciphertext)
        plaintext_bytes = unpad(decrypted_padded_bytes, AES.block_size)
        return plaintext_bytes.decode('utf-8')

    elif mode == "CFB":
        # Extract the IV from the beginning of the data.
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        plaintext_bytes = cipher.decrypt(ciphertext)
        return plaintext_bytes.decode('utf-8')

    else:
        raise ValueError("Unsupported mode. Please choose 'ECB', 'CBC', or 'CFB'.")

selected_mode = input("Select a mode (ECB, CBC, CFB): ")

key = get_random_bytes(16)  # AES-128 key
plaintext = "This is a secret message for the DPS lab exam."

print("--- AES Encryption Demonstration ---")

print(f"Mode Selected:    {selected_mode}")
print(f"Original Plaintext: {plaintext}")
print(f"AES Key (hex):      {key.hex()}")

# 2. Encryption
encrypted = encrypt(plaintext, key, selected_mode)

# 3. Print IV (if applicable) and Ciphertext
# For modes that use an IV, we extract it from the combined data to print it.
if selected_mode != "ECB":
    iv = encrypted[:AES.block_size]
    print(f"IV (hex):           {iv.hex()}")

print(f"Encrypted (hex):    {encrypted.hex()}")

# 4. Decryption
decrypted = decrypt(encrypted, key, selected_mode)
print(f"\nDecrypted Plaintext: {decrypted}")

# 5. Verification
if decrypted == plaintext:
   print("\nVerification Successful: Decrypted text matches the original.")
else:
   print("\nVerification Failed: Decrypted text does not match.")

#RSA
# RSA Encryption & Decryption Demonstration
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt(plaintext, public_key):
    # Convert plaintext string to bytes
    plaintext_bytes = plaintext.encode('utf-8')

    # Create an RSA encryptor with OAEP padding
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext_bytes)

    return ciphertext

def decrypt(ciphertext, private_key):
    # Create an RSA decryptor with OAEP padding
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_bytes = cipher.decrypt(ciphertext)

    return decrypted_bytes.decode('utf-8')


# === Main Script ===
print("--- RSA Encryption & Decryption Demonstration ---")

# 1. Key Generation
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

print("RSA Keys Generated (2048-bit).")
print(f"Public Key (PEM):\n{public_key.export_key().decode()[:100]}...\n")
print(f"Private Key (PEM):\n{private_key.export_key().decode()[:100]}...\n")

# 2. Define plaintext
plaintext = "RSA is used to securely exchange the secret key for AES."
print(f"Original Plaintext: {plaintext}")

# 3. Encryption
ciphertext = encrypt(plaintext, public_key)
print(f"\nEncrypted (hex): {ciphertext.hex()}")

# 4. Decryption
decrypted_text = decrypt(ciphertext, private_key)
print(f"\nDecrypted Plaintext: {decrypted_text}")

# 5. Verification
if decrypted_text == plaintext:
    print("\nVerification Successful: Decrypted text matches the original.")
else:
    print("\nVerification Failed: Decrypted text does not match.")
