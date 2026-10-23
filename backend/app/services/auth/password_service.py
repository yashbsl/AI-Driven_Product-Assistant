
from __future__ import annotations

from passlib.context import CryptContext


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


class PasswordService:
    """Handle password hashing, verification, and validation."""

    MAX_BCRYPT_PASSWORD_BYTES = 72

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt with safe length validation."""
        if not isinstance(password, str):
            raise ValueError("Password must be a string.")

        if len(password.encode("utf-8")) > PasswordService.MAX_BCRYPT_PASSWORD_BYTES:
            raise ValueError(
                "Password is too long. Bcrypt passwords must not exceed "
                "72 UTF-8 bytes."
            )

        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain: str, hashed: str) -> bool:
        """Verify a plaintext password against its stored hash."""
        if not isinstance(plain, str) or not isinstance(hashed, str):
            return False

        if len(plain.encode("utf-8")) > PasswordService.MAX_BCRYPT_PASSWORD_BYTES:
            return False

        if not hashed:
            return False

        try:
            return pwd_context.verify(plain, hashed)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_password_strength(
        password: str,
    ) -> tuple[bool, list[str]]:
        """Validate password length and strength."""
        errors: list[str] = []

        if not isinstance(password, str):
            return False, ["Password must be a string."]

        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")

        if not any(char.isdigit() for char in password):
            errors.append("Password must contain at least one digit.")

        if not any(char.isupper() for char in password):
            errors.append("Password must contain at least one uppercase letter.")

        if len(password.encode("utf-8")) > PasswordService.MAX_BCRYPT_PASSWORD_BYTES:
            errors.append("Password must not exceed 72 UTF-8 bytes.")

        return len(errors) == 0, errors


password_service = PasswordService()
