"""
Matcher/filter helpers for ffuf-style response selection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class NumberSpec:
    ranges: tuple[tuple[int, int], ...]

    def matches(self, value: int) -> bool:
        return any(start <= value <= end for start, end in self.ranges)


def parse_number_spec(raw: str | None) -> NumberSpec | None:
    if not raw:
        return None

    ranges: list[tuple[int, int]] = []
    for part in raw.split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            left, right = item.split("-", 1)
            start = int(left.strip())
            end = int(right.strip())
            if start > end:
                start, end = end, start
            ranges.append((start, end))
        else:
            value = int(item)
            ranges.append((value, value))

    return NumberSpec(tuple(ranges)) if ranges else None


def number_matches(spec: str | None, value: int) -> bool:
    parsed = parse_number_spec(spec)
    return parsed.matches(value) if parsed else False


def regex_matches(pattern: str | None, value: str) -> bool:
    if not pattern:
        return False
    return re.search(pattern, value, re.IGNORECASE | re.MULTILINE) is not None


def validate_regex(pattern: str | None) -> bool:
    if not pattern:
        return True
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False
