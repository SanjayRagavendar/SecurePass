import keyring as kr

class KeyringManager:
    @staticmethod
    def get_keyring():
        return kr.get_keyring()

    @staticmethod
    def set_password(username, password):
        kr.set_password("PasswordManager", username, password)

    @staticmethod
    def get_password(username):
        return kr.get_password("PasswordManager", username)

    @staticmethod
    def delete_password(username):
        kr.delete_password("PasswordManager", username)