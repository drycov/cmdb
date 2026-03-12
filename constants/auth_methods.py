from enum import StrEnum


class AuthMethod(StrEnum):
    PRIMARY = "primary"
    FALLBACK = "fallback"