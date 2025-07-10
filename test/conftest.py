"""
Shared pytest configuration and fixtures
"""
import pytest
import sys
import os

# Add the project root to Python path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture(scope="session")
def test_data_dir():
    """Provide a directory for test data files"""
    return os.path.join(os.path.dirname(__file__), "data")

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Setup that runs before each test"""
    # Any setup code that should run before each test
    pass
