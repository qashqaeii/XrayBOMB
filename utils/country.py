"""Country code utilities and flag emoji helpers."""

from __future__ import annotations

import re
import sys
import tkinter.font as tkfont
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tkinter import Text

# Regional indicator pairs (flag emojis) and common single emoji symbols.
FLAG_EMOJI_RE = re.compile(
    r"[\U0001F1E6-\U0001F1FF]{2}|\U0001F3F3(?:\uFE0F)?(?:\U0001F3F4[\U000E0061-\U000E007A]+)?"
)


def emoji_font_family() -> str:
    """Return a platform font that renders color flag emojis."""
    candidates = {
        "win32": ("Segoe UI Emoji", "Segoe UI Symbol"),
        "darwin": ("Apple Color Emoji",),
    }.get(sys.platform, ("Noto Color Emoji", "Segoe UI Emoji"))
    try:
        available = set(tkfont.families())
        for name in candidates:
            if name in available:
                return name
    except Exception:
        pass
    return candidates[0]

# ISO 3166-1 alpha-2 → English country name (common set)
COUNTRY_NAMES: dict[str, str] = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra",
    "AO": "Angola", "AR": "Argentina", "AM": "Armenia", "AU": "Australia",
    "AT": "Austria", "AZ": "Azerbaijan", "BH": "Bahrain", "BD": "Bangladesh",
    "BY": "Belarus", "BE": "Belgium", "BO": "Bolivia", "BA": "Bosnia",
    "BR": "Brazil", "BG": "Bulgaria", "KH": "Cambodia", "CA": "Canada",
    "CL": "Chile", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
    "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic",
    "DK": "Denmark", "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt",
    "SV": "El Salvador", "EE": "Estonia", "ET": "Ethiopia", "FI": "Finland",
    "FR": "France", "GE": "Georgia", "DE": "Germany", "GH": "Ghana",
    "GR": "Greece", "GT": "Guatemala", "HN": "Honduras", "HK": "Hong Kong",
    "HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia",
    "IR": "Iran", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel",
    "IT": "Italy", "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan",
    "KE": "Kenya", "KR": "South Korea", "KW": "Kuwait", "LV": "Latvia",
    "LB": "Lebanon", "LY": "Libya", "LT": "Lithuania", "LU": "Luxembourg",
    "MY": "Malaysia", "MX": "Mexico", "MD": "Moldova", "MN": "Mongolia",
    "MA": "Morocco", "MM": "Myanmar", "NP": "Nepal", "NL": "Netherlands",
    "NZ": "New Zealand", "NI": "Nicaragua", "NG": "Nigeria", "NO": "Norway",
    "OM": "Oman", "PK": "Pakistan", "PA": "Panama", "PY": "Paraguay",
    "PE": "Peru", "PH": "Philippines", "PL": "Poland", "PT": "Portugal",
    "QA": "Qatar", "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia",
    "RS": "Serbia", "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia",
    "ZA": "South Africa", "ES": "Spain", "LK": "Sri Lanka", "SE": "Sweden",
    "CH": "Switzerland", "SY": "Syria", "TW": "Taiwan", "TH": "Thailand",
    "TR": "Turkey", "UA": "Ukraine", "AE": "United Arab Emirates",
    "GB": "United Kingdom", "US": "United States", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam", "YE": "Yemen",
}


def country_flag(code: str | None) -> str:
    """Return flag emoji from ISO 3166-1 alpha-2 code."""
    if not code or len(code) != 2:
        return "🏳️"
    return "".join(chr(ord(c) + 127397) for c in code.upper())


def country_name(code: str | None) -> str:
    """Return English country name from code."""
    if not code:
        return "Unknown"
    return COUNTRY_NAMES.get(code.upper(), code.upper())


def format_country(code: str | None, name: str | None = None) -> str:
    """Format country with flag and name."""
    if not code and not name:
        return "Unknown"
    flag = country_flag(code)
    display = name or country_name(code)
    code_part = f" ({code.upper()})" if code else ""
    return f"{flag} {display}{code_part}"


def apply_flag_emoji_tags(text_widget: "Text", size: int = 12) -> None:
    """Tag flag emoji ranges with a font that renders them as graphics."""
    family = emoji_font_family()
    tag = "flag_emoji"
    text_widget.tag_configure(tag, font=(family, size))
    content = text_widget.get("1.0", "end-1c")
    text_widget.tag_remove(tag, "1.0", "end")
    for match in FLAG_EMOJI_RE.finditer(content):
        start = f"1.0+{match.start()}c"
        end = f"1.0+{match.end()}c"
        text_widget.tag_add(tag, start, end)
