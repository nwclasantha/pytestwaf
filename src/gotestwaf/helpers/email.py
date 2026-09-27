"""Email validation utilities."""

from __future__ import annotations

from email_validator import EmailNotValidError, validate_email as _validate_email

from gotestwaf.errors import ValidationError

MAX_EMAIL_LENGTH = 254


def validate_email(email: str) -> str:
    """Validate and normalize an email address.

    Args:
        email: The email address string to validate.

    Returns:
        The normalized email address.

    Raises:
        ValidationError: If the email is invalid or too long.
    """
    try:
        result = _validate_email(email, check_deliverability=False)
    except EmailNotValidError as e:
        msg = f"couldn't parse email: {e}"
        raise ValidationError(msg) from e

    normalized = result.normalized
    if len(normalized) > MAX_EMAIL_LENGTH:
        msg = "email too long"
        raise ValidationError(msg)

    return normalized
