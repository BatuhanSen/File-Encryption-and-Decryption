from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def get_password():
    while True:
        password = input("Enter a strong password: ")
        if (
            any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~" for c in password)
        ):
            return password
        else:
            print("Weak password. Please include at least one uppercase letter, one lowercase letter, one digit, and one special character.")

def encrypt_file_cbc(file_path, password):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Padding ekleme işlemi
    plaintext = plaintext + b'\0' * (16 - len(plaintext) % 16)

    salt = os.urandom(16)
    iv = os.urandom(16)  # Initialization Vector
    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # HMAC oluşturma
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    hmac_value = h.finalize()

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(salt + iv + ciphertext + hmac_value)

    # Orijinal dosyayı silme işlemi
    os.remove(file_path)

def decrypt_file_cbc(encrypted_file_path, password):
    with open(encrypted_file_path, 'rb') as encrypted_file:
        data = encrypted_file.read()

    if len(data) < 64:
        print("Error: Invalid encrypted file format.")
        return

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32: -32]
    hmac_value = data[-32:]

    key = generate_key(password, salt)

    # HMAC doğrulama
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)

    try:
        h.verify(hmac_value)
    except Exception as e:
        print(f"Error: {e}")
        return

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Padding kaldırma işlemi
    decrypted_data = decrypted_data.rstrip(b'\0')

    original_file_path = encrypted_file_path[:-4]  # Remove the '.enc' extension
    with open(original_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    # Şifre çözüldükten sonra şifrelenmiş versiyonu silme işlemi
    os.remove(encrypted_file_path)

# Kullanıcıdan işlem seçimini al
while True:
    choice = input("Encrypt (e) or Decrypt (d)? Enter 'q' to quit: ").lower()

    if choice == 'q':
        break
    elif choice == 'e':
        password = get_password()
        file_path = input("Enter the path of the file to encrypt: ")
        encrypt_file_cbc(file_path, password)
        print("File encrypted successfully.")
    elif choice == 'd':
        password = get_password()
        encrypted_file_path = input("Enter the path of the file to decrypt: ")
        decrypt_file_cbc(encrypted_file_path, password)
        print("File decrypted successfully.")
    else:
        print("Invalid choice. Please enter 'e', 'd', or 'q'.")
