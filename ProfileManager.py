from CryptoManager import CryptoManager

import os
import getpass
import json

class ProfileManager:

    def __init__(self):

        self.CM = CryptoManager()

        self.SP = CryptoManager.SessionProtection(self.CM)
        
        self.PROFILE_PATHS = {'linux': '/home/',
                              'windows': 'c:\\users\\'}
        
        self.CheckingOperationSystem()
        self.SetDefaultProfilePath()
        self.CheckingExistsDirectroy()

    def CheckingExistsDirectroy(self):
        folder_exists = os.path.isdir(self.DEFAULT_PROFILE_PATH)

        if folder_exists == False:
            self.CreateDirectorys()


    def CreateDirectorys(self):
        print(os.mkdir(self.DEFAULT_PROFILE_PATH))
    
    def CheckingOperationSystem(self):
        temp = os.name
        if temp == 'posix':
            self.OS = 'linux'
        
        elif temp == 'nt':
            self.OS = 'windows'

        self.USERNAME = getpass.getuser()
        del temp

    def SetDefaultProfilePath(self):
        if self.OS == 'linux':
            self.DEFAULT_PROFILE_PATH = self.PROFILE_PATHS[self.OS]+self.USERNAME+'/.SimplePassSecrets'
        elif self.OS == 'windows':
            self.DEFAULT_PROFILE_PATH = self.PROFILE_PATHS[self.OS]+self.USERNAME+'\\SimplePassSecrets'

    def CreateNewProfile(self, profile_name):
        
        
        data = {'profile': {'name': profile_name, 'status': 'inactive', 'secrets': {}}}
        self.SaveProfileData(profile_name, data)

        print(f'Был создан новый профиль "{profile_name}"')

    def ActivateProfile(self, profile_name):
        profile_data = self.LoadDataFromProfile(profile_name)
        if profile_data != False:
            if self.CheckActiveProfile(profile_data):
                print('Этот профиль уже активен!')
            else:
                print('Для активации профиля требуется придумать парольную фразу.\nПарольная фраза должна легко запоминаться и быть длинной не менее 20 символов.')

                passphrase = self.SP.EncryptSessionData(getpass.getpass('Введите парольную фразу: '))
                passphrase_check = self.SP.EncryptSessionData(getpass.getpass('Повторите парольную фразу: '))
                
                if len(self.SP.DecryptSessionData(passphrase)) >= 20:
                    if passphrase == passphrase_check:
                        print('Парольные фразы совпали! Проводится тестирования ключа шифрования...')
                        
                        encrypt_data = self.CM.EncryptAES256(self.CM.DEFAULT_PLAINTEXT, self.CM.CreateAESKey(self.SP.DecryptSessionData(passphrase)))
                        decrypt_data = self.SP.EncryptSessionData(self.CM.DecryptAES256(encrypt_data[0], self.CM.CreateAESKey(self.SP.DecryptSessionData(passphrase)), encrypt_data[1]))

                        if self.SP.DecryptSessionData(decrypt_data) == self.CM.DEFAULT_PLAINTEXT:
                            print('Процесс шифрования и дешифрования прошёл успешно!\nТеперь в этот профиль можно добавлять данные авторизации на ресурсы!')
                            encrypt_data = self.CM.EncryptAES256(self.CM.DEFAULT_PLAINTEXT, self.CM.CreateAESKey(self.SP.DecryptSessionData(passphrase)))

                            profile_data['profile']['status'] = 'active'
                            profile_data['profile']['secrets'].update({'test_text': {'text': encrypt_data[0].hex(), 'salt': encrypt_data[1]}})

                            
                            self.SaveProfileData(profile_name, profile_data)


                            self.SP.DeleteSessionData()
                            del decrypt_data, encrypt_data, passphrase, passphrase_check
                        
                        else:
                            print('Произошла непредвиденная ошибка при тестировании ключа шифрования!')
                    else:
                        print('Парольные фразы не совпадают!')
                else:
                    print('Длинна парольной фразы составляет менее 20 символов!')


    def RemoveProfile(self, profile_name):
        profile_data = self.LoadDataFromProfile(profile_name)

        print('Вы уверенны что хотите удалить профиль, указанный ниже:')
        print(profile_data['profile']['name'], '->', profile_data['profile']['status'])
        print('\nЕсли вы точно хотите удалить этот профиль, то введите "' + f'delete profile {profile_data["profile"]["name"]}' + '"\n')
        text = input('--> ')
        if text == f'delete profile {profile_data["profile"]["name"]}':
            os.remove(self.DEFAULT_PROFILE_PATH+f'/{profile_name}.json')
            if os.path.isfile(self.DEFAULT_PROFILE_PATH+f'/{profile_name}.json') != True:
                print(f'Профиль {profile_name} успешно удалён!')

    def AddingAuthorizationData(self, profile_name, resource_name):

        
        profile_data = self.LoadDataFromProfile(profile_name)

        if profile_data != False:

        
            passphrase = self.SP.EncryptSessionData(self.CM.GetPassphrase())

            if self.CheckResourceExists(profile_data, resource_name):
            
                checking_out_data, profile_data = self.CheckProfileKey(profile_data, resource_name, passphrase)

                if checking_out_data:
                    login = self.SP.EncryptSessionData(input('Введите логин: '))
                    password = self.SP.EncryptSessionData(getpass.getpass('Введите пароль: '))
                    password_check = self.SP.EncryptSessionData(getpass.getpass('Повторите пароль: '))
                    if self.SP.DecryptSessionData(password) == self.SP.DecryptSessionData(password_check):
                        
                        text = ''

                        if len(login) != 0:
                            text = self.SP.EncryptSessionData(self.SP.DecryptSessionData(login) + ' / ' + self.SP.DecryptSessionData(password))
                        else:
                            text = password

                        encrypt_data = self.CM.EncryptAES256(self.SP.DecryptSessionData(text), self.CM.CreateAESKey(self.SP.DecryptSessionData(passphrase)))

                        profile_data['profile']['secrets'].update({resource_name: {'cipher': encrypt_data[0].hex(), 'salt': encrypt_data[1]}})

                        self.SaveProfileData(profile_name, profile_data)

                        print('Ресурс успешно добавлен!')

                        self.SP.DeleteSessionData()
                        del profile_data, encrypt_data, text, password, passphrase, password_check

                    else:
                        print('Пароли не совпали!')
                else:
                    print('Ошибка при проверке ключа шифрования!')
            else:
                print('Такой ресурс уже существует')

    def GetResourceSecret(self, profile_name, resource_name):

        profile_data = self.LoadDataFromProfile(profile_name)

        if profile_data != False:
        
            if self.CheckResourceExists(profile_data, resource_name) == False:
            
                print('Убедитесь, что на экран не направлены чужие взгляды!')

                              
                passphrase = self.SP.EncryptSessionData(self.CM.GetPassphrase())
                
                checking_out_data, profile_data = self.CheckProfileKey(profile_data, resource_name, passphrase)

                if checking_out_data:
                    
                    decrypt_data = self.SP.EncryptSessionData(self.CM.DecryptAES256(bytes.fromhex(profile_data['profile']['secrets'][resource_name]['cipher']),
                                                        self.CM.CreateAESKey(self.SP.DecryptSessionData(passphrase)),
                                                        profile_data['profile']['secrets'][resource_name]['salt']))
                    
                    
                    new_data, new_salt = self.CM.EncryptAES256(self.SP.DecryptSessionData(decrypt_data), self.CM.CreateAESKey(self.SP.DecryptSessionData(passphrase)))

                    profile_data['profile']['secrets'][resource_name]['cipher'] = new_data.hex()
                    profile_data['profile']['secrets'][resource_name]['salt'] = new_salt

                    print(self.SP.DecryptSessionData(decrypt_data))

                    self.SaveProfileData(profile_name, profile_data)
                    
                    self.SP.DeleteSessionData()
                    del profile_data, new_data, new_salt, decrypt_data, passphrase
                    
                    input('Когда будите готовы, нажмите Enter...')
                    
                    if self.OS == 'linux':
                        os.system('clear')
                    elif self.OS == 'windows':
                        os.system('cls')
                else:
                    print('Возникла неизвественая ошибка!')
            else:
                print('Этот ресурс не указан в прифиле!')

    def RemoveResource(self, profile_name, resource_name):

        profile_data = self.LoadDataFromProfile(profile_name)

        if profile_data != False:

            if self.CheckResourceExists(profile_data, resource_name) == False:

                passphrase = self.SP.EncryptSessionData(self.CM.GetPassphrase())
                checking_out_data, profile_data = self.CheckProfileKey(profile_data, resource_name, passphrase)

                if checking_out_data:

                    print(f'Вы уверенны что хотите удалить секреты ресурса {resource_name}? (yes/no)')

                    if input(': ') == 'yes':
                        profile_data['profile']['secrets'].pop(resource_name, None)
                    else:
                        print('Отказ в удалении секрета.')

                    self.SaveProfileData(profile_name, profile_data)

                    self.SP.DeleteSessionData()
                    del passphrase, profile_data
                else:
                    print('Возникла неизвестная ошибка!')
            else:
                print('Ресурса с таким именем не существует!')
        
    def EditResourceSecret(self, profile_name, resource_name):

        profile_data = self.LoadDataFromProfile(profile_name)

        if profile_data != False:

            if self.CheckResourceExists(profile_data, resource_name) == False:

                passphrase = self.SP.EncryptSessionData(self.CM.GetPassphrase())

                checking_out_data, profile_data = self.CheckProfileKey(profile_data, resource_name, passphrase)

                if checking_out_data:

                    login = self.SP.EncryptSessionData(input('Введите новый логин: '))
                    password = self.SP.EncryptSessionData(getpass.getpass('Введите новый пароль: '))
                    password_check = self.SP.EncryptSessionData(getpass.getpass('Повторите новый пароль: '))
                    if self.SP.DecryptSessionData(password) == self.SP.DecryptSessionData(password_check):
                        
                        text = ''

                        if len(login) != 0:
                            text = self.SP.EncryptSessionData(self.SP.DecryptSessionData(login) + ' / ' + self.SP.DecryptSessionData(password))
                        else:
                            text = password

                        encrypt_data = self.CM.EncryptAES256(self.SP.DecryptSessionData(text), self.CM.CreateAESKey(self.SP.DecryptSessionData(passphrase)))

                        profile_data['profile']['secrets'][resource_name] = {'cipher': encrypt_data[0].hex(), 'salt': encrypt_data[1]}

                        self.SaveProfileData(profile_name, profile_data)

                        print('Ресурс успешно изменён!')

                        self.SP.DeleteSessionData()
                        del profile_data, encrypt_data, text, password, passphrase, password_check
                    else:
                        print('Введённые пароли не одинаковы!')
                else:
                    print('Возникла неизвестная ошибка!')
            else:
                print('Ресурса с таким именем не существует!')

    def GeneratePasswords(self, data):

        passwords = []

        for i in range(data[1]):

            passwords.append(self.CM.SaltGenerate(data[0]))

        with open(self.DEFAULT_PROFILE_PATH+'/passwords.secret', 'w') as file:

            file.write('\n'.join(passwords))

        del passwords
        print(f'Файд с паролями сохранён в {self.DEFAULT_PROFILE_PATH}/passwords.secret\nНе забудьте удалить файл после использования!')


    def ListResource(self, profile_name):

        profile_data = self.LoadDataFromProfile(profile_name)

        print(f'Секреты из профиля "{profile_name}":\n')

        index = 1

        for i in profile_data['profile']['secrets']:
            if i == 'test_text':
                continue
            print(f'{index}) {i}')
            index += 1

    def ListProfiles(self):
        files = os.listdir(self.DEFAULT_PROFILE_PATH)

        if len(files) != 0:

            for i in files:
                data = self.LoadDataFromProfile(i)
                if data != False:
                    line = data['profile']['name'] + '  ->  ' + data['profile']['status'] 
                    print(line)
        else:
            print('Никаких профилей не существует!')

    def LoadDataFromProfile(self, profile_name):
        try:
            if profile_name[-5:] != '.json':
                profile_name += '.json'

            if self.OS == 'linux':
                with open(self.DEFAULT_PROFILE_PATH+f'/{profile_name}', 'r') as f:
                    data = dict(json.loads(f.read()))
            elif self.OS == 'windows':
                with open(self.DEFAULT_PROFILE_PATH+f'\\{profile_name}', 'r') as f:
                    data = dict(json.loads(f.read()))

        except Exception:
            self.ProfileNotFoundError()
            return False
        else:
            return data
        
    def GetTestData(self, data):

        cipher_text = bytes.fromhex(data['profile']['secrets']['test_text']['text'])
        salt = data['profile']['secrets']['test_text']['salt']

        return [cipher_text, salt]
        

    def SaveProfileData(self, profile_name, data):
        with open(self.DEFAULT_PROFILE_PATH+f'/{profile_name}.json', 'w') as file:
            file.write(json.dumps(data, indent=4))

    def CheckActiveProfile(self, profile_data):

        if profile_data['profile']['status'] != 'inactive':
            return True
        else:
            return False

    def CheckResourceExists(self, data, resource_name):
        
        try:
           data['profile']['secrets'][resource_name]['salt']
        except KeyError:
            return True
        else:
            return False
        

    def ProfileNotFoundError(self):
        print('Профиль с таким именем не найден или уже существует!')


    def CheckProfileKey(self, profile_data, resource_name, passphrase):

        test_data = self.GetTestData(profile_data)

        checking_out_data, profile_data = self.CM.CheckingKey(test_data[0], test_data[1], self.CM.CreateAESKey(self.SP.DecryptSessionData(passphrase)), profile_data)
        
        return checking_out_data, profile_data
        