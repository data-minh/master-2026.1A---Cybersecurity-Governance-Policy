import pytest

from services.orchestrator.app.ledger import CursorError, decode_cursor, encode_cursor


def test_opaque_cursor_round_trip_and_validation():
    cursor = encode_cursor(19)
    assert cursor != "19"
    assert decode_cursor(cursor) == 19
    with pytest.raises(CursorError):
        decode_cursor("not base64!")
    with pytest.raises(CursorError):
        decode_cursor("a" * 257)
