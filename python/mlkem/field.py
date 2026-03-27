"""Finite field arithmetic modulo Q = 3329."""
from __future__ import annotations

Q = 3329


def mod_q(a: int) -> int:
    """Reduce a modulo Q into range [0, Q)."""
    return a % Q


def field_add(a: int, b: int) -> int:
    """Add two field elements modulo Q."""
    return (a + b) % Q


def field_sub(a: int, b: int) -> int:
    """Subtract two field elements modulo Q."""
    return (a - b) % Q


def field_mul(a: int, b: int) -> int:
    """Multiply two field elements modulo Q."""
    return (a * b) % Q


def field_pow(base: int, exp: int) -> int:
    """Raise a field element to a power modulo Q."""
    return pow(base, exp, Q)
