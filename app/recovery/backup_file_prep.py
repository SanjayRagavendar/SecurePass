from app.db.db_vault import VaultDB
from app.db.db_users import UserDB
from app.db.vault_model import PasswordVault
from app.config import BACKUP_DIR
import json

class BackupFilePrep:
    def __init__(self, user_name: str):
        self.user_name = user_name
        self.vault_db = VaultDB(user_name)
        userdb = UserDB()
        self.user = userdb.get_user(user_name) 
        self.backup_file_path = f"{BACKUP_DIR}/{self.user_name}_vault_backup.json"

    def prepare_backup(self) -> str:
        password_data = self.vault_db.get_all_passwords()

        base_data = {
            "version": "1.0",
            "user_id": self.user.id,
            "user_name": self.user_name,
            "salt": self.user.salt.decode('utf-8'),
            "encrypted_text": self.user.encrypted_text.decode('utf-8'),
            "created_at": self.user.created_at.isoformat(),
            "last_access_at": self.user.last_access_at.isoformat(),
            "recovery_key_hash": self.user.recovery_key_hash.decode('utf-8'),
            "passwords": []
        }
        for password in password_data:
            base_data["passwords"].append({
                "website": password.website,
                "username": password.username,
                "password": password.password.decode('utf-8'),
                "notes": password.notes.decode('utf-8') if password.notes else None
            })

        with open(self.backup_file_path, 'w') as backup_file:
            json.dump(base_data, backup_file, indent=4)

        return self.backup_file_path
    
    def restore_backup(self, backup_file_path: str) -> None:
        with open(backup_file_path, 'r') as backup_file:
            data = json.load(backup_file)

        userdb = UserDB()
        userdb.register_user(
            username=data["user_name"],
            salt=data["salt"].encode('utf-8'),
            encrypted_text=data["encrypted_text"].encode('utf-8')
        )

        for password in data["passwords"]:
            self.vault_db.add_password(
                PasswordVault(
                    user_name=data["user_name"],
                    website=password["website"],
                    username=password["username"],
                    password=password["password"].encode('utf-8'),
                    notes=password["notes"].encode('utf-8') if password["notes"] else None
                )
            )