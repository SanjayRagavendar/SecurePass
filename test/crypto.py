import pytest
import os
import base64
from cryptography.fernet import Fernet
from app.crypto import CryptoManager


class TestCryptoManager:
    """Test suite for CryptoManager class"""
    
    @pytest.fixture
    def sample_password(self):
        """Fixture providing a sample master password"""
        return "test_master_password_123"
    
    @pytest.fixture
    def sample_salt(self):
        """Fixture providing a sample salt"""
        return b'sample_salt_16__'  # 16 bytes
    
    @pytest.fixture
    def crypto_manager(self, sample_password, sample_salt):
        """Fixture providing a CryptoManager instance"""
        return CryptoManager(sample_password, sample_salt)
    
    @pytest.fixture
    def sample_data(self):
        """Fixture providing sample data to encrypt"""
        return b"This is secret data that needs to be encrypted"

    def test_crypto_manager_initialization(self, sample_password, sample_salt):
        """Test CryptoManager initialization"""
        crypto = CryptoManager(sample_password, sample_salt)
        
        assert crypto.salt == sample_salt
        assert crypto.key is not None
        assert crypto.fernet is not None
        assert isinstance(crypto.fernet, Fernet)

    def test_derive_key_consistency(self, sample_password, sample_salt):
        """Test that derive_key produces consistent results"""
        crypto1 = CryptoManager(sample_password, sample_salt)
        crypto2 = CryptoManager(sample_password, sample_salt)
        
        # Same password and salt should produce same key
        assert crypto1.key == crypto2.key

    def test_derive_key_different_passwords(self, sample_salt):
        """Test that different passwords produce different keys"""
        crypto1 = CryptoManager("password1", sample_salt)
        crypto2 = CryptoManager("password2", sample_salt)
        
        assert crypto1.key != crypto2.key

    def test_derive_key_different_salts(self, sample_password):
        """Test that different salts produce different keys"""
        salt1 = b'salt1_16_bytes__'
        salt2 = b'salt2_16_bytes__'
        
        crypto1 = CryptoManager(sample_password, salt1)
        crypto2 = CryptoManager(sample_password, salt2)
        
        assert crypto1.key != crypto2.key

    def test_encrypt_decrypt_roundtrip(self, crypto_manager, sample_data):
        """Test that encrypt/decrypt operations work correctly"""
        # Encrypt the data
        encrypted = crypto_manager.encrypt(sample_data)
        
        # Verify encrypted data is different from original
        assert encrypted != sample_data
        assert len(encrypted) > len(sample_data)  # Encrypted data should be larger
        
        # Decrypt the data
        decrypted = crypto_manager.decrypt(encrypted)
        
        # Verify decrypted data matches original
        assert decrypted == sample_data

    def test_encrypt_produces_different_outputs(self, crypto_manager, sample_data):
        """Test that encrypting the same data twice produces different outputs"""
        encrypted1 = crypto_manager.encrypt(sample_data)
        encrypted2 = crypto_manager.encrypt(sample_data)
        
        # Due to Fernet's use of random IV, each encryption should be different
        assert encrypted1 != encrypted2
        
        # But both should decrypt to the same original data
        assert crypto_manager.decrypt(encrypted1) == sample_data
        assert crypto_manager.decrypt(encrypted2) == sample_data

    def test_encrypt_empty_data(self, crypto_manager):
        """Test encrypting empty data"""
        empty_data = b""
        encrypted = crypto_manager.encrypt(empty_data)
        decrypted = crypto_manager.decrypt(encrypted)
        
        assert decrypted == empty_data

    def test_encrypt_large_data(self, crypto_manager):
        """Test encrypting large data"""
        large_data = b"x" * 10000  # 10KB of data
        encrypted = crypto_manager.encrypt(large_data)
        decrypted = crypto_manager.decrypt(encrypted)
        
        assert decrypted == large_data

    def test_decrypt_invalid_token(self, crypto_manager):
        """Test that decrypting invalid data raises an exception"""
        invalid_token = b"invalid_encrypted_data"
        
        with pytest.raises(Exception):  # Fernet will raise InvalidToken
            crypto_manager.decrypt(invalid_token)

    def test_decrypt_with_wrong_key(self, sample_data, sample_salt):
        """Test that data encrypted with one key cannot be decrypted with another"""
        crypto1 = CryptoManager("password1", sample_salt)
        crypto2 = CryptoManager("password2", sample_salt)
        
        encrypted = crypto1.encrypt(sample_data)
        
        with pytest.raises(Exception):  # Should raise InvalidToken
            crypto2.decrypt(encrypted)

    def test_generate_salt(self):
        """Test salt generation"""
        salt1 = CryptoManager.generate_salt()
        salt2 = CryptoManager.generate_salt()
        
        # Should be 16 bytes (SALT_LENGTH)
        assert len(salt1) == 16
        assert len(salt2) == 16
        
        # Should be different each time
        assert salt1 != salt2
        
        # Should be bytes
        assert isinstance(salt1, bytes)
        assert isinstance(salt2, bytes)

    def test_generate_recovery_key(self):
        """Test recovery key generation"""
        key1 = CryptoManager.generate_recovery_key()
        key2 = CryptoManager.generate_recovery_key()
        
        # Should be different each time
        assert key1 != key2
        
        # Should be valid Fernet keys (44 bytes when base64 encoded)
        assert len(key1) == 44
        assert len(key2) == 44
        
        # Should be bytes
        assert isinstance(key1, bytes)
        assert isinstance(key2, bytes)
        
        # Should be valid base64
        try:
            base64.urlsafe_b64decode(key1)
            base64.urlsafe_b64decode(key2)
        except Exception:
            pytest.fail("Generated keys should be valid base64")

    def test_fernet_compatibility_with_recovery_key(self, sample_data):
        """Test that generated recovery keys work with Fernet"""
        recovery_key = CryptoManager.generate_recovery_key()
        fernet = Fernet(recovery_key)
        
        # Should be able to encrypt and decrypt with the recovery key
        encrypted = fernet.encrypt(sample_data)
        decrypted = fernet.decrypt(encrypted)
        
        assert decrypted == sample_data

    @pytest.mark.parametrize("password,expected_type", [
        ("simple", bytes),
        ("complex_password_123!@#", bytes),
        ("unicode_café_🔐", bytes),
        ("", bytes),  # Empty password
    ])
    def test_derive_key_with_various_passwords(self, expected_type, password):
        """Test key derivation with various password types"""
        salt = CryptoManager.generate_salt()
        crypto = CryptoManager(password, salt)
        
        assert isinstance(crypto.key, expected_type)
        assert len(crypto.key) == 44  # Base64 encoded 32-byte key

    def test_encrypt_decrypt_unicode_strings(self, crypto_manager):
        """Test encrypting and decrypting unicode strings"""
        unicode_text = "Hello 世界 🌍 café"
        unicode_bytes = unicode_text.encode('utf-8')
        
        encrypted = crypto_manager.encrypt(unicode_bytes)
        decrypted = crypto_manager.decrypt(encrypted)
        
        assert decrypted == unicode_bytes
        assert decrypted.decode('utf-8') == unicode_text


# Integration tests
class TestCryptoManagerIntegration:
    """Integration tests for CryptoManager"""
    
    def test_full_workflow_simulation(self):
        """Test a complete password manager workflow"""
        # 1. Generate salt for new user
        salt = CryptoManager.generate_salt()
        
        # 2. User sets master password
        master_password = "user_master_password_123"
        crypto = CryptoManager(master_password, salt)
        
        # 3. Encrypt some passwords
        passwords = [
            b"gmail_password_123",
            b"facebook_secure_pass",
            b"banking_password_456"
        ]
        
        encrypted_passwords = []
        for password in passwords:
            encrypted_passwords.append(crypto.encrypt(password))
        
        # 4. Verify all passwords can be decrypted
        for i, encrypted in enumerate(encrypted_passwords):
            decrypted = crypto.decrypt(encrypted)
            assert decrypted == passwords[i]
        
        # 5. Test that wrong master password fails
        wrong_crypto = CryptoManager("wrong_password", salt)
        with pytest.raises(Exception):
            wrong_crypto.decrypt(encrypted_passwords[0])

    def test_recovery_key_workflow(self):
        """Test recovery key generation and usage"""
        # Generate recovery key
        recovery_key = CryptoManager.generate_recovery_key()
        
        # Use recovery key directly with Fernet
        fernet = Fernet(recovery_key)
        
        # Encrypt some data
        secret_data = b"recovery_test_data"
        encrypted = fernet.encrypt(secret_data)
        
        # Decrypt with same recovery key
        decrypted = fernet.decrypt(encrypted)
        assert decrypted == secret_data


if __name__ == "__main__":
    # Run tests if script is executed directly
    pytest.main([__file__, "-v"])