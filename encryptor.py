from Crypto.Cipher import AES
import base64

def encrypt_message(key, message):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_message(key, encrypted_message):
    encrypted_data = base64.b64decode(encrypted_message)
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

if __name__ == "__main__":
    key = input("Enter a 16-character key: ")
    message = input("Enter the message to encrypt: ")

    encrypted = encrypt_message(key, message)
    print("Encrypted:", encrypted)

    decrypted = decrypt_message(key, encrypted)
    print("Decrypted:", decrypted)