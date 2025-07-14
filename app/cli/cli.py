import os
from app.crypto import CryptoManager
from app.db.db_users import UserDB
from app.db.db_vault import VaultDB
from app.config import APP_Data, DB_FILE, BACKUP_DIR, USERS_DIR, LOG_DIR, LOG_FILE
import getpass
from datetime import datetime
import shutil
import hashlib

class PasswordManagerCLI:
    def __init__(self):
        self.user_db = UserDB()
        self.vault_db = None  # Will be initialized after user login
        self.crypto_manager = None  # Will be initialized after user login
        self.current_user = None
        self.current_token = None
        
    def banner(self):
        print("""
        ╔══════════════════════════════════════════════════════════╗
        ║            Password Manager CLI Framework                ║
        ║                                                          ║
        ║    Type 'help' for available commands                    ║
        ║    Type 'exit' to quit                                   ║
        ╚══════════════════════════════════════════════════════════╝
        """)
    
    def prompt(self):
        if self.current_user:
            return f"securePass[{self.current_user}]> "
        return "securePass> "

    def help_menu(self):
        print("\nCore Commands:")
        print("  help              - Show this help menu")
        print("  exit              - Exit the application")
        print("  clear             - Clear the screen")
        print("  init              - Initialize required directories")
        print("  backup            - Create database backup")
        
        print("\nUser Management:")
        print("  create-user       - Create a new user")
        print("  list-users        - List all users")
        print("  login             - Login as a user")
        print("  logout            - Logout current user")
        
        if self.current_user:
            print("\nVault Commands (authenticated):")
            print("  add-password      - Add a new password entry")
            print("  list-passwords    - List password entries")
            print("  get-password      - Get a specific password")
            print("  update-password   - Update a password entry")
            print("  delete-password   - Delete a password entry")
    
    def create_user(self):
        username = input("Enter username: ")
        if self.user_db.user_exists(username):
            print(f"[-] Error: User '{username}' already exists")
            return
        
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("[-] Error: Passwords do not match")
            return
        
        try:
            # Generate a salt for this user
            salt = CryptoManager.generate_salt()
            
            # Create a crypto manager instance for this user
            crypto = CryptoManager(password, salt)
            
            # Create an encrypted verification token
            # We'll use username as the verification data
            encrypted_text = crypto.encrypt(username.encode())
            
            # Generate a recovery key hash
            recovery_key = CryptoManager.generate_recovery_key()
            recovery_key_hash = hashlib.sha256(recovery_key).digest()
            
            # Register the user
            success = self.user_db.register_user(
                username=username,
                salt=salt,
                encrypted_text=encrypted_text,
                recovery_key_hash=recovery_key_hash
            )
            
            if success:
                # Create a vault DB for this user
                vault_db = VaultDB(username)
                
                print(f"[+] User '{username}' created successfully")
                print(f"[!] IMPORTANT: Here is your recovery key. Keep it safe:")
                print(f"    {recovery_key.decode()}")
                print(f"    This key will not be shown again!")
            else:
                print("[-] Error creating user")
                
        except Exception as e:
            print(f"[-] Error creating user: {str(e)}")
    
    def login(self):
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        try:
            # Try using login_user first, which stores decrypted text
            user = self.user_db.login_user(username, password)
            
            if user:
                self.current_user = username
                
                # Initialize crypto manager with user's password and salt
                self.crypto_manager = CryptoManager(password, user.salt)
                
                # Initialize vault DB for this user
                self.vault_db = VaultDB(username)
                
                print(f"[+] Successfully logged in as {username}")
            else:
                print("[-] Invalid credentials")
        except Exception as e:
            print(f"[-] Login error: {str(e)}")
    
    def logout(self):
        if self.current_user:
            print(f"[+] Logged out from {self.current_user}")
            self.current_user = None
            self.crypto_manager = None
            self.vault_db = None
        else:
            print("[-] No user logged in")
    
    def list_users(self):
        users = self.user_db.get_all_users()
        if users:
            print("\n[+] Users:")
            for user in users:
                print(f"    {user}")
        else:
            print("[-] No users found")
    
    def add_password(self):
        if not self.current_user:
            print("[-] Please login first")
            return
        
        website = input("Website/Service: ")
        username = input("Username/Email: ")
        password = getpass.getpass("Password: ")
        notes = input("Notes (optional): ")
        
        # Get user data to get user ID
        user = self.user_db.get_user(self.current_user)
        
        try:
            # Encrypt the password with the user's crypto manager
            encrypted_password = self.crypto_manager.encrypt(password.encode())
            
            # Encrypt notes if provided
            encrypted_notes = None
            if notes:
                encrypted_notes = self.crypto_manager.encrypt(notes.encode())
            
            # Add the password to the vault
            if self.vault_db.add_password(
                user_id=user.id,
                website=website,
                username=username,
                password=encrypted_password,
                notes=encrypted_notes
            ):
                print("[+] Password entry added successfully")
            else:
                print("[-] Error adding password entry")
        except Exception as e:
            print(f"[-] Error adding password: {str(e)}")
    
    def list_passwords(self):
        if not self.current_user:
            print("[-] Please login first")
            return
        
        try:
            entries = self.vault_db.get_all_passwords()
            
            if entries:
                print("\n[+] Password entries:")
                print(f"{'ID':<5} | {'Website':<30} | {'Username':<30}")
                print("-" * 70)
                
                for entry in entries:
                    print(f"{entry.id:<5} | {entry.website:<30} | {entry.username:<30}")
            else:
                print("[-] No password entries found")
        except Exception as e:
            print(f"[-] Error listing passwords: {str(e)}")
    
    def get_password(self):
        if not self.current_user:
            print("[-] Please login first")
            return
        
        website = input("Website/Service: ")
        
        try:
            entry = self.vault_db.get_password(website)
            
            if entry:
                # Decrypt the password
                decrypted_password = self.crypto_manager.decrypt(entry.password).decode()
                
                # Decrypt notes if available
                notes = None
                if entry.notes:
                    notes = self.crypto_manager.decrypt(entry.notes).decode()
                
                print("\n[+] Password details:")
                print(f"Website/Service: {entry.website}")
                print(f"Username/Email: {entry.username}")
                print(f"Password: {decrypted_password}")
                if notes:
                    print(f"Notes: {notes}")
            else:
                print(f"[-] No password found for '{website}'")
        except Exception as e:
            print(f"[-] Error retrieving password: {str(e)}")
    
    def update_password(self):
        if not self.current_user:
            print("[-] Please login first")
            return
        
        website = input("Website/Service: ")
        
        try:
            entry = self.vault_db.get_password(website)
            
            if not entry:
                print(f"[-] No password found for '{website}'")
                return
                
            new_password = getpass.getpass("New password: ")
            confirm_password = getpass.getpass("Confirm new password: ")
            
            if new_password != confirm_password:
                print("[-] Passwords do not match")
                return
            
            # Encrypt the new password
            encrypted_password = self.crypto_manager.encrypt(new_password.encode())
            
            # Update the password
            if self.vault_db.update_password(website, encrypted_password):
                print("[+] Password updated successfully")
            else:
                print("[-] Error updating password")
        except Exception as e:
            print(f"[-] Error updating password: {str(e)}")
    
    def delete_password(self):
        if not self.current_user:
            print("[-] Please login first")
            return
        
        website = input("Website/Service: ")
        
        try:
            entry = self.vault_db.get_password(website)
            
            if not entry:
                print(f"[-] No password found for '{website}'")
                return
                
            confirm = input(f"Are you sure you want to delete the password for '{website}'? (y/n): ")
            
            if confirm.lower() != 'y':
                print("[-] Operation cancelled")
                return
            
            if self.vault_db.delete_password(website):
                print("[+] Password deleted successfully")
            else:
                print("[-] Error deleting password")
        except Exception as e:
            print(f"[-] Error deleting password: {str(e)}")
    
    def backup_database(self):
        if not self.current_user:
            print("[-] Please login first to create a backup")
            return
            
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
        
        try:
            from app.recovery.backup_file_prep import BackupFilePrep
            
            backup = BackupFilePrep(self.current_user)
            backup_path = backup.prepare_backup()
            
            print(f"[+] Backup created successfully: {backup_path}")
        except Exception as e:
            print(f"[-] Error creating backup: {str(e)}")
    
    def init_directories(self):
        directories = [APP_Data, BACKUP_DIR, USERS_DIR, LOG_DIR]
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"[+] Created directory: {directory}")
    
    def run(self):
        self.banner()
        self.init_directories()  # Ensure directories exist
        
        while True:
            try:
                command = input(self.prompt()).strip().lower()
                
                if command in ['exit', 'quit']:
                    print("Goodbye!")
                    break
                elif command == 'help':
                    self.help_menu()
                elif command == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                elif command == 'create-user':
                    self.create_user()
                elif command == 'login':
                    self.login()
                elif command == 'logout':
                    self.logout()
                elif command == 'list-users':
                    self.list_users()
                elif command == 'add-password':
                    self.add_password()
                elif command == 'list-passwords':
                    self.list_passwords()
                elif command == 'get-password':
                    self.get_password()
                elif command == 'update-password':
                    self.update_password()
                elif command == 'delete-password':
                    self.delete_password()
                elif command == 'backup':
                    self.backup_database()
                elif command == 'init':
                    self.init_directories()
                elif command == '':
                    continue
                else:
                    print(f"[-] Unknown command: {command}")
                    print("Type 'help' for available commands")
                    
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except EOFError:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"[-] Error: {str(e)}")

def main():
    cli = PasswordManagerCLI()
    cli.run()

if __name__ == '__main__':
    main()