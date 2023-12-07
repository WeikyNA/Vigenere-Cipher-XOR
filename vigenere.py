def vigenere_encrypt(plaintext, key):
    encrypted_text = ""
    key_stream = generate_key_stream(plaintext, key)
    
    for char, key_char in zip(plaintext, key_stream):
        encrypted_char = chr(ord(char) ^ ord(key_char))
        encrypted_text += encrypted_char

    return encrypted_text

def vigenere_decrypt(ciphertext, key):
    decrypted_text = ""
    key_stream = generate_key_stream(ciphertext, key)
    
    for char, key_char in zip(ciphertext, key_stream):
        decrypted_char = chr(ord(char) ^ ord(key_char))
        decrypted_text += decrypted_char

    return decrypted_text

def generate_key_stream(text, key):
    key_stream = ""
    key_length = len(key)
    
    for i in range(len(text)):
        key_stream += key[i % key_length]

    return key_stream

def main():
    plaintext = "PastiBisa"
    key = "Key123"

    # Enkripsi
    ciphertext = vigenere_encrypt(plaintext, key)
    print(f"Plaintext: {plaintext}")
    print(f"Key: {key}")
    print(f"Encrypted Text: {ciphertext}")

    # Dekripsi
    decrypted_text = vigenere_decrypt(ciphertext, key)
    print(f"\nDecrypted Text: {decrypted_text}")

if __name__ == "__main__":
    main()
