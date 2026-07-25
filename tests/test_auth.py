"""
Tests for the Auth module.
Covers: register, login, refresh, /me, change-password, RBAC.
"""
import pytest
from httpx import AsyncClient

from src.models.user import User, UserRole


# ── Registration ──────────────────────────────────────────────────────────────
class TestRegister:
    async def test_register_success(self, client: AsyncClient):
        resp = await client.post("/api/auth/register", json={
            "email": "new@test.mras",
            "full_name": "New User",
            "password": "secure123",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "new@test.mras"
        assert data["role"] == "employee"          # default role
        assert "hashed_password" not in data       # never exposed

    async def test_register_duplicate_email(self, client: AsyncClient, sample_employee: User):
        resp = await client.post("/api/auth/register", json={
            "email": "employee@test.mras",         # already exists
            "full_name": "Duplicate",
            "password": "secure123",
        })
        assert resp.status_code == 400
        assert "already exists" in resp.json()["detail"]

    async def test_register_weak_password_too_short(self, client: AsyncClient):
        resp = await client.post("/api/auth/register", json={
            "email": "weak@test.mras",
            "full_name": "Weak Password",
            "password": "abc",              # too short
        })
        assert resp.status_code == 422

    async def test_register_password_no_digit(self, client: AsyncClient):
        resp = await client.post("/api/auth/register", json={
            "email": "nodigit@test.mras",
            "full_name": "No Digit",
            "password": "onlyletters",      # no number
        })
        assert resp.status_code == 422

    async def test_register_invalid_email(self, client: AsyncClient):
        resp = await client.post("/api/auth/register", json={
            "email": "not-an-email",
            "full_name": "Bad Email",
            "password": "secure123",
        })
        assert resp.status_code == 422

    async def test_register_with_doctor_role(self, client: AsyncClient):
        resp = await client.post("/api/auth/register", json={
            "email": "doc@test.mras",
            "full_name": "A Doctor",
            "password": "secure123",
            "role": "doctor",
        })
        assert resp.status_code == 201
        assert resp.json()["role"] == "doctor"


# ── Login ─────────────────────────────────────────────────────────────────────
class TestLogin:
    async def test_login_success(self, client: AsyncClient, sample_employee: User):
        resp = await client.post("/api/auth/login", json={
            "email": "employee@test.mras",
            "password": "password123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == "employee@test.mras"

    async def test_login_wrong_password(self, client: AsyncClient, sample_employee: User):
        resp = await client.post("/api/auth/login", json={
            "email": "employee@test.mras",
            "password": "wrongpassword",
        })
        assert resp.status_code == 401

    async def test_login_wrong_email(self, client: AsyncClient):
        resp = await client.post("/api/auth/login", json={
            "email": "nobody@test.mras",
            "password": "password123",
        })
        assert resp.status_code == 401

    async def test_login_inactive_user(
        self, client: AsyncClient, sample_employee: User
    ):
        sample_employee.is_active = False
        await sample_employee.save()

        resp = await client.post("/api/auth/login", json={
            "email": "employee@test.mras",
            "password": "password123",
        })
        assert resp.status_code == 401
        assert "deactivated" in resp.json()["detail"]


# ── Token Refresh ─────────────────────────────────────────────────────────────
class TestRefresh:
    async def test_refresh_success(self, client: AsyncClient, sample_employee: User):
        login_resp = await client.post("/api/auth/login", json={
            "email": "employee@test.mras",
            "password": "password123",
        })
        refresh_token = login_resp.json()["refresh_token"]

        resp = await client.post("/api/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    async def test_refresh_with_invalid_token(self, client: AsyncClient):
        resp = await client.post("/api/auth/refresh", json={
            "refresh_token": "this.is.not.valid",
        })
        assert resp.status_code == 401

    async def test_refresh_with_access_token_fails(
        self, client: AsyncClient, employee_token: str
    ):
        """Access tokens must not be accepted as refresh tokens."""
        resp = await client.post("/api/auth/refresh", json={
            "refresh_token": employee_token,
        })
        assert resp.status_code == 401


# ── /me Endpoint ──────────────────────────────────────────────────────────────
class TestGetMe:
    async def test_get_me_authenticated(
        self, client: AsyncClient, employee_token: str
    ):
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {employee_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "employee@test.mras"

    async def test_get_me_unauthenticated(self, client: AsyncClient):
        resp = await client.get("/api/auth/me")
        assert resp.status_code == 401

    async def test_get_me_invalid_token(self, client: AsyncClient):
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert resp.status_code == 401


# ── Change Password ───────────────────────────────────────────────────────────
class TestChangePassword:
    async def test_change_password_success(
        self, client: AsyncClient, employee_token: str
    ):
        resp = await client.post(
            "/api/auth/change-password",
            json={"current_password": "password123", "new_password": "newpass456"},
            headers={"Authorization": f"Bearer {employee_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == "Password changed successfully"

        # Verify old password no longer works
        login_resp = await client.post("/api/auth/login", json={
            "email": "employee@test.mras",
            "password": "password123",
        })
        assert login_resp.status_code == 401

        # Verify new password works
        login_resp2 = await client.post("/api/auth/login", json={
            "email": "employee@test.mras",
            "password": "newpass456",
        })
        assert login_resp2.status_code == 200

    async def test_change_password_wrong_current(
        self, client: AsyncClient, employee_token: str
    ):
        resp = await client.post(
            "/api/auth/change-password",
            json={"current_password": "wrongcurrent", "new_password": "newpass456"},
            headers={"Authorization": f"Bearer {employee_token}"},
        )
        assert resp.status_code == 400


# ── RBAC ──────────────────────────────────────────────────────────────────────
class TestRBAC:
    async def test_security_hash_not_in_response(
        self, client: AsyncClient, employee_token: str
    ):
        """Hashed password must never appear in any API response."""
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {employee_token}"},
        )
        response_text = resp.text
        assert "hashed_password" not in response_text
        assert "$2b$" not in response_text   # bcrypt hash prefix

    async def test_doctor_can_access_own_profile(
        self, client: AsyncClient, doctor_token: str
    ):
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {doctor_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "doctor"