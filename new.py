import hashlib

def encrypt_reference_id(reference_id):
    sha256 = hashlib.sha256()
    sha256.update(reference_id.encode('utf-8'))
    encrypted_reference_id = sha256.hexdigest()
    return encrypted_reference_id

def decrypt_reference_id(encrypted_reference_id):
    # Decryption is not possible as it uses a one-way hash function (SHA-256)
    return "Decryption not supported for one-way hash functions"

def validate_reference_id(reference_id):
    # Allow alphanumeric and some special characters in Reference ID
    return len(reference_id) >= 8 and reference_id.isascii()

def main():
    reference_id = input("Enter Reference ID: ")

    if validate_reference_id(reference_id):
        encrypted_id = encrypt_reference_id(reference_id)
        print("Encrypted Reference ID:", encrypted_id)

        # Ask user if they want to decrypt
        decrypt_option = input("Do you want to decrypt the Reference ID? (yes/no): ").lower()

        if decrypt_option == "yes":
            decrypted_id = decrypt_reference_id(encrypted_id)
            print("Decrypted Reference ID:", decrypted_id)
        elif decrypt_option != "no":
            print("Invalid option. Please enter 'yes' or 'no'.")
    else:
        print("Invalid Reference ID. It should be at least 8 characters long and consist of ASCII characters.")

if __name__ == "__main__":
    main()
