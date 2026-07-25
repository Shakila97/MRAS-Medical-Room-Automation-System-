import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient
from beanie import init_beanie

from src.main import app
from src.core.config import settings
from src.modules.user import User, UserRole
from src.core.security import hash_password
from src.models import (
    Patient, Vital, Consultation, Drug, Prescription, PrescriptionLine,
    InventoryItem, GRN, GRNLot, JRISSIRecord, Appointment,
    Notification, ForecastSignal, AuditLog
)

TEST_DATABASE_URL = "mongodb://localhost:27017/mras_test_db"

@pytest_asyncio.fixture(scope="session", autouse=True)
async def init_beanie_for_tests():
    """Initialize Beanie with a mock MongoDB client for the test session."""
    settings.DATABASE_URL = TEST_DATABASE_URL
    mock_client = AsyncMongoMockClient()
    
    # We patch the database initialization to use our mock client
    from src.core import database
    # Overwrite the actual init_db so the app lifespan uses the mock
    async def mock_init_db():
        await init_beanie(
            database=mock_client.get_database("mras_test_db"),
            document_models=[
                User, Patient, Vital, Consultation, Drug, Prescription,
                PrescriptionLine, InventoryItem, GRN, GRNLot,
                JRISSIRecord, Appointment, Notification,
                ForecastSignal, AuditLog
            ]
        )
    database.init_db = mock_init_db
    
    # Also initialize it right now for tests
    await mock_init_db()
    
    yield mock_client

@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_test_db(init_beanie_for_tests):
    """Clear collections before each test."""
    mock_client = init_beanie_for_tests
    db = mock_client.get_database("mras_test_db")
    
    # Drop collections to start fresh
    for collection_name in await db.list_collection_names():
        await db.drop_collection(collection_name)
    yield

@pytest_asyncio.fixture
async def client() -> AsyncClient:
    """Yield an async HTTP test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

@pytest_asyncio.fixture
async def sample_employee() -> User:
    """A pre-created employee user for use in tests."""
    user = User(
        email="employee@test.mras",
        full_name="Test Employee",
        employee_id="SIS/24/B2/99",
        hashed_password=hash_password("password123"),
        role=UserRole.EMPLOYEE,
        is_active=True,
    )
    await user.insert()
    return user

@pytest_asyncio.fixture
async def sample_doctor() -> User:
    """A pre-created doctor user for use in tests."""
    user = User(
        email="doctor@test.mras",
        full_name="Dr. Test Doctor",
        hashed_password=hash_password("password123"),
        role=UserRole.DOCTOR,
        is_active=True,
    )
    await user.insert()
    return user

@pytest_asyncio.fixture
async def sample_admin() -> User:
    """A pre-created admin user for use in tests."""
    user = User(
        email="admin@test.mras",
        full_name="System Admin",
        hashed_password=hash_password("password123"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    await user.insert()
    return user

@pytest_asyncio.fixture
async def employee_token(client: AsyncClient, sample_employee: User) -> str:
    """Login as employee and return the access token."""
    resp = await client.post("/api/auth/login", json={
        "email": "employee@test.mras",
        "password": "password123",
    })
    return resp.json()["access_token"]

@pytest_asyncio.fixture
async def doctor_token(client: AsyncClient, sample_doctor: User) -> str:
    """Login as doctor and return the access token."""
    resp = await client.post("/api/auth/login", json={
        "email": "doctor@test.mras",
        "password": "password123",
    })
    return resp.json()["access_token"]

@pytest_asyncio.fixture
async def admin_token(client: AsyncClient, sample_admin: User) -> str:
    """Login as admin and return the access token."""
    resp = await client.post("/api/auth/login", json={
        "email": "admin@test.mras",
        "password": "password123",
    })
    return resp.json()["access_token"]