
#ADDITIVE CIPHER
def additive_cipher(text, key, mode='encrypt'):
    text_lower = text.lower()
    result = ""

    for char in text_lower:
        if char.isalpha():
            if mode == 'encrypt':
                # C = (P + k) % 26
                new_char_code = (ord(char) - ord('a') + key) % 26
            elif mode == 'decrypt':
                # P = (C - k) % 26
                new_char_code = (ord(char) - ord('a') - key) % 26

            result += chr(new_char_code + ord('a'))
        else:
            result += char

    # Preserve case style: if input was all uppercase → output uppercase
    if text.isupper():
        return result.upper()
    else:
        return result


# Example usage
plaintext = input("Enter the plaintext: ")
key = int(input("Enter the key value: "))

print(f"Plaintext: '{plaintext}'")
print(f"Key: {key}")

encrypted_message = additive_cipher(plaintext, key, mode='encrypt')
print(f"Encrypted: '{encrypted_message}'")

decrypted_message = additive_cipher(encrypted_message, key, mode='decrypt')
print(f"Decrypted: '{decrypted_message}'")

if decrypted_message == plaintext:
    print("Decryption successful!")
else:
    print("Decryption failed.")
    
    
    
    
#MULTIPLICATIVE CIPHER
import math

# Extended Euclidean Algorithm
def find_modular_inverse(a, m):
    if math.gcd(a, m) != 1:
        return None  # No inverse exists.
    r1, r2 = a, m
    s1, s2 = 1, 0
    m0 = m

    while r2 > 0:
        q = r1 // r2
        r = r1 - q * r2
        r1, r2 = r2, r

        s = s1 - q * s2
        s1, s2 = s2, s

    if s1 < 0:
        s1 += m0
    return s1


def multiplicative_cipher(text, key, mode='encrypt'):
    mod_inverse = find_modular_inverse(key, 26)
    if mod_inverse is None:
        return f"Error: Key '{key}' is not valid. It must be coprime with 26."

    text_lower = text.lower()
    result = ""

    for char in text_lower:
        if char.isalpha():
            p_val = ord(char) - ord('a')

            if mode == 'encrypt':
                # C = (P * key) mod 26
                c_val = (p_val * key) % 26
                result += chr(c_val + ord('a'))
            elif mode == 'decrypt':
                # P = (C * key_inverse) mod 26
                p_val_decrypted = (p_val * mod_inverse) % 26
                result += chr(p_val_decrypted + ord('a'))
        else:
            result += char

    # Preserve case style: if input was ALL CAPS → return ALL CAPS
    if text.isupper():
        return result.upper()
    else:
        return result


# Example usage
plaintext = input("Enter the plaintext: ")
key = int(input("Enter the key value: "))

print(f"Plaintext: '{plaintext}'")
print(f"Key: {key}")

print("\n--- Encryption ---")
encrypted_message = multiplicative_cipher(plaintext, key, mode='encrypt')
print(f"Encrypted: '{encrypted_message}'")

print("\n--- Decryption ---")
decrypted_message = multiplicative_cipher(encrypted_message, key, mode='decrypt')
print(f"Decrypted: '{decrypted_message}'")

if decrypted_message == plaintext:
    print("Decryption successful!")
else:
    print("Decryption failed.")
    
    
#AFFINE CIPHER
import math

#extended euclidean algorithm
def find_modular_inverse(a, m):
    if math.gcd(a, m) != 1:
        return None  # No inverse exists.
    r1, r2 = a, m
    s1, s2 = 1, 0

    m0 = m
    while r2 > 0:
        q = r1 // r2

        r = r1 - q * r2
        r1, r2 = r2, r

        # Update the coefficients for 'a' (s).
        s = s1 - q * s2
        s1, s2 = s2, s

    # If s1 is negative, convert it to its positive equivalent in the modulus.
    if s1 < 0:
        s1 += m0
    return s1


def affine_cipher(text, key_a, key_b, mode='encrypt'):
    """
    key_a (k1): The multiplicative key.
    key_b (k2): The additive key.
    """
    mod_inverse_a = find_modular_inverse(key_a, 26)
    if mod_inverse_a is None:
        return f"Error: Multiplicative key 'a' ({key_a}) is not valid. It must be coprime with 26."

    result = ""
    text_lower = text.lower()

    for char in text_lower:
        if char.isalpha():
            p_val = ord(char) - ord('a')
            if mode == 'encrypt':
                # C = (P * k1 + k2) mod 26
                c_val = (key_a * p_val + key_b) % 26
                new_char = chr(c_val + ord('a'))
            elif mode == 'decrypt':
                # P = ((C - k2) * k1_inv) mod 26
                p_val_decrypted = (mod_inverse_a * (p_val - key_b)) % 26
                new_char = chr(p_val_decrypted + ord('a'))
                2
            result += new_char
        else:
            result += char # Keep non-alphabetic characters

    # Preserve case style: if input was ALL CAPS → return ALL CAPS
    if text.isupper():
        return result.upper()
    else:
        return result

plaintext = input("Enter the plaintext: ")
key_a = int(input("Enter the multiplicative key (k1 or a): "))
key_b = int(input("Enter the additive key (k2 or b): "))

print(f"Plaintext: '{plaintext}'")
print(f"Keys: (a={key_a}, b={key_b})")


encrypted_message = affine_cipher(plaintext, key_a, key_b, mode='encrypt')
print(f"Encrypted: '{encrypted_message}'")

decrypted_message = affine_cipher(encrypted_message, key_a, key_b, mode='decrypt')
print(f"Decrypted: '{decrypted_message}'")

if decrypted_message == plaintext:
   print("\nVerification successful: Decryption matches original plaintext.")
else:
   print("\nVerification failed. Check the logic or keys.")