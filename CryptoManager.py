import hashlib
import os
import random
import getpass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class CryptoManager:

    def __init__(self):
        
        self.DEFAULT_PLAINTEXT = 'test plaintext'


    def GetPassphrase(self):
        
        print('Введите парольную фразу профиля:\n')

        return getpass.getpass('--> ')
    
    def CheckingKey(self, cipher_text, salt, aes_key, profile_data):

        try:

            if self.DEFAULT_PLAINTEXT == self.DecryptAES256(cipher_text, aes_key, salt):
                new_cipher_text, salt = self.EncryptAES256(self.DEFAULT_PLAINTEXT, aes_key)
                
                profile_data['profile']['secrets']['test_text']['cipher'] = new_cipher_text.hex()
                profile_data['profile']['secrets']['test_text']['salt'] = salt
                return True, profile_data
            else:
                return False, False
        except Exception:
            return False, False
            

    def CreateAESKey(self, text: str) -> bytes:
            aes_key = hashlib.sha256(text.encode()).digest()
            return aes_key
        
    def EncryptAES256(self, plaintext: str, key: bytes, session_data=None) -> bytes:
        
        if session_data == None:
            salt = self.SaltGenerate(len(plaintext)//2)
            iv = os.urandom(16)
        else:
            salt, iv = session_data

        plaintext = self.SaltInserting(plaintext, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return [iv + ciphertext, salt]
    
    def DecryptAES256(self, ciphertext: bytes, key: bytes, created_salt=None, session_data=None) -> str:

        salt = ''
        if created_salt != None:
            salt = created_salt
        elif session_data != None:
            salt = session_data[0]
        
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        return self.RemoveSalt(plaintext.decode(), salt)
    
    def SaltGenerate(self, symbol_count):
        symbols = {
        'a': 'qwertyuiopasdfghjklzxcvbnm',
        'numbers': '0123456789',
        'spe': '`~!@#$%^&*()_+-=[]{};:\'"\\|,<.>/?'}
    
        result = ''
        
        for i in range(symbol_count):
            sym = ''
            doing_var = random.choice(['a', 'numbers', 'spe'])
            if doing_var == 'a':
                sym = random.choice(list(symbols[doing_var]))
                if random.randint(1, 2) == 2:
                    sym = sym.upper()
                
            elif doing_var == 'numbers':
                sym = random.choice(list(symbols[doing_var]))
            elif doing_var == 'spe':
                sym = random.choice(list(symbols[doing_var]))
                
            result += sym
            
        return result
    
    def SaltInserting(self, line, salt):
        sep = round(len(line) / len(salt)) # каждый раз, когда нужно вставлять символ
        
        result = ''
        
        a = 0 # какой символ соли использовать
        b = 0 # какой символ отработан
        all_count_salt_symbol = 0
        
        for i in line:
            if b // sep == 1:
                result += list(salt)[a] + i
                a += 1
                b = 1
                all_count_salt_symbol += 1
            else:
                result += i
                b += 1

        if all_count_salt_symbol == len(salt)-1:
            result += salt[-1]
        
        return result
    
    def RemoveSalt(self, line, salt):

        plain_text_symbol_count = len(line) - len(salt)
        sep = round(plain_text_symbol_count / len(salt))

        result = ''

        index = 0

        all_count_salt_symbol = 0
        
        for i in line:
            if index // sep == 1:
                index = 0
                all_count_salt_symbol += 1
            else:
                result += i
                index += 1
            
        if all_count_salt_symbol == len(salt)-1:
            result = result[:-1]
        
        return result
    
    class SessionProtection:

        def __init__(self, CM):

            self.CM = CM

            self.CreateSessionKey()
            self.CreateSessionProtectionData()

        
        def CreateSessionKey(self):

            os.environ['PASSWORD_MANAGER_SESSION_KEY'] = self.CM.CreateAESKey(self.CM.SaltGenerate(20)).hex()

        def GetSessionKey(self):

            return bytes.fromhex(os.environ['PASSWORD_MANAGER_SESSION_KEY'])
        
        def CreateSessionProtectionData(self):

            self.session_data = [
                self.CM.SaltGenerate(len(self.CM.DEFAULT_PLAINTEXT)//3),
                os.urandom(16)
            ]

        def EncryptSessionData(self, text):
            return self.CM.EncryptAES256(text, self.GetSessionKey(), self.session_data)[0]

        def DecryptSessionData(self, cipher_text):
            return self.CM.DecryptAES256(cipher_text, self.GetSessionKey(), session_data=self.session_data)
        
        def DeleteSessionData(self):
            
            os.environ['PASSWORD_MANAGER_SESSION_KEY'] = 'Im removed :('

            del self.session_data, self.CM
