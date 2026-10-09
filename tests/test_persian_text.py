"""Tests for Persian text display helpers."""

from utils.persian_text import (
    contains_persian,
    format_rtl_line,
    is_ltr_line,
    reshape_mixed,
    split_persian_lines,
)


def test_contains_persian():
    assert contains_persian("سلام")
    assert not contains_persian("hello only")


def test_technical_lines_stay_ltr():
    assert is_ltr_line("  Protocol        : VLESS")
    assert is_ltr_line("     bash <(curl -Ls https://example.com/install.sh)")
    assert is_ltr_line("       proxy_set_header Host example.com;")


def test_step_line_moves_number_to_visual_start():
    raw = "  ۱. VPS خارج از ایران بخرید (Hetzner)."
    shaped = format_rtl_line(raw)
    assert shaped.endswith(" .۱")
    assert "VPS" in shaped
    assert shaped.strip().startswith("VPS") or "VPS" in shaped


def test_split_mixed_document():
    text = "  Protocol        : VLESS\n  ۱. VPS خارج از ایران بخرید.\n"
    rows = split_persian_lines(text)
    assert rows[0][1] == "ltr"
    assert rows[1][1] == "rtl"


def test_reshape_connects_persian():
    raw = "سلام"
    shaped = reshape_mixed(raw)
    assert shaped
    assert shaped != raw or len(raw) == 1
