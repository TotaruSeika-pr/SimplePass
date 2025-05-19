from ProfileManager import ProfileManager

import argparse

class ArgumentsManager:

    def __init__(self):
        
        self.PM = ProfileManager()
        
        self.parser = argparse.ArgumentParser(
                    prog='PasswordManager',
                    description='Менеджер паролей с надёжным шифрованием')
        
        self.ArgumentInitialization()
        
        self.args = self.parser.parse_args()

        self.CheckingArguments()

    def ArgumentInitialization(self):
        self.parser.add_argument('-cp', '--create-profile', action='store_true', help='Создание нового профиля.')
        self.parser.add_argument('-ap', '--activate-profile', action='store_true', help='Активирует неактивный профиль.')
        self.parser.add_argument('-lp', '--list-profiles', action='store_true', help='Вывод всех существующих профилей.')
        self.parser.add_argument('-rp', '--remove-profile', action='store_true', help='Удаляет уже существующий профиль.')
        self.parser.add_argument('-ar', '--add-resource', action='store_true', help='Добавляет данные авторизации.')
        self.parser.add_argument('-gr', '--get-resource', action='store_true', help='Получить секрет из ресурса профиля.')
        self.parser.add_argument('-lr', '--list-resource', action='store_true', help='Выводит список всех добавленных ресурсов профиля.')
        self.parser.add_argument('-rr', '--remove-resource', action='store_true', help='Удаляет выбранный ресурс профиля.')
        self.parser.add_argument('-er', '--edit-resource', action='store_true', help='Применяется для редактирования ресурса.')
        self.parser.add_argument('-chp', '--change-passphrase', action='store_true', help='Позволяет изменить парольную фразу профиля.')

        self.parser.add_argument('-p', '--profile', default=None, type=str, help='Указыват рабочий профиль')
        self.parser.add_argument('-r', '--resource', default=None, type=str, help='Указывается в случае работы с записью на ресурс.')

        self.parser.add_argument('-gp', '--generate-password', nargs=2, default=None ,type=int, help='Генератор случайных паролей.\nПолсе написания укажите количество символов в пароле и количество самих паролей.')

    def CheckingArguments(self):
        if self.args.create_profile and self.ProfileCheck():
            self.PM.CreateNewProfile(self.args.profile)

        elif self.args.activate_profile and self.ProfileCheck():
            self.PM.ActivateProfile(self.args.profile)

        elif self.args.list_profiles:
            self.PM.ListProfiles()

        elif self.args.remove_profile and self.ProfileCheck():
            self.PM.RemoveProfile(self.args.profile)

        elif self.args.add_resource and self.ProfileCheck() and self.ResourceCheck():
            self.PM.AddingAuthorizationData(self.args.profile, self.args.resource)

        elif self.args.list_resource and self.ProfileCheck():
            self.PM.ListResource(self.args.profile)
        
        elif self.args.get_resource and self.ProfileCheck() and self.ResourceCheck():
            self.PM.GetResourceSecret(self.args.profile, self.args.resource)

        elif self.args.remove_resource and self.ProfileCheck() and self.ResourceCheck():
            self.PM.RemoveResource(self.args.profile, self.args.resource)

        elif self.args.edit_resource and self.ProfileCheck() and self.ResourceCheck():
            self.PM.EditResourceSecret(self.args.profile, self.args.resource)

        elif self.args.change_passphrase and self.ProfileCheck():
            self.PM.ChangePassphraseProfile(self.args.profile)

        elif self.args.generate_password != None:
            self.PM.GeneratePasswords(self.args.generate_password)
            
        else:
            print('Неверно указаны атрибуты!')

    def ProfileCheck(self):
        if self.args.profile != None:
            return True
        else:
            return False
        
    def ResourceCheck(self):
        if self.args.resource != None:
            return True
        else:
            return False