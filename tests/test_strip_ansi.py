
def test_terminal_output_buffer_splits_prompt():
    from utils.helpers import TerminalOutputBuffer

    buf = TerminalOutputBuffer()
    assert buf.feed("cert h") == ""
    assert buf.feed("root@ubuntu:~# ") == "cert h\nroot@ubuntu:~# \n"


def test_clean_terminal_chunk_carriage_return():
    from utils.helpers import clean_terminal_chunk

    assert clean_terminal_chunk("line1\rline2\n") == "line1\nline2\n"
    assert clean_terminal_chunk("root@h:~# ls\rcert\rroot@h:~# \n") == "root@h:~# ls\ncert\nroot@h:~# \n"


def test_strip_ansi_colors_and_modes():
    from utils.helpers import strip_ansi

    raw = "\x1b[01;34mcert\x1b[0m\n\x1b[?2004h"
    assert strip_ansi(raw) == "cert\n"


def test_strip_ansi_orphan_csi():
    from utils.helpers import strip_ansi

    assert strip_ansi("[01;34mcert[0m") == "cert"
    assert strip_ansi("plain text") == "plain text"
