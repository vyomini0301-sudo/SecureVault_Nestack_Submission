
import os
from pathlib import Path


def positive_int(name, default, minimum=1, maximum=None):
    value = int(os.getenv(name, str(default)))

    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")

    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")

    return value


class Config:
    DATABASE = os.getenv(
        "DATABASE_PATH",
        str(Path(__file__).parent / "securevault.db")
    )

    SESSION_TTL_SECONDS = positive_int(
        "SESSION_TTL_SECONDS", 3600
    )

    LOCKOUT_SECONDS = positive_int(
        "LOCKOUT_SECONDS", 900
    )

    MAX_FAILED_LOGINS = positive_int(
        "MAX_FAILED_LOGINS", 5
    )

    BCRYPT_ROUNDS = positive_int(
        "BCRYPT_ROUNDS", 12, minimum=4, maximum=16
    )

    RATE_LIMIT_ENABLED = (
        os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    )

    RATE_LIMIT_REQUESTS = positive_int(
        "RATE_LIMIT_REQUESTS", 60
    )

    RATE_LIMIT_WINDOW_SECONDS = positive_int(
        "RATE_LIMIT_WINDOW_SECONDS", 60
    )
