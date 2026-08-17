import pytest

from phantomtap.formats import ALL_FORMATS, get_format


@pytest.mark.parametrize("fmt", ALL_FORMATS, ids=lambda f: f.name)
def test_encode_decode_roundtrip(fmt):
    # Clamp facility values so 0-facility formats (e.g. H10302) stay in range.
    for fc, cn in [(0, 0), (min(1, fmt.max_facility), 1),
                   (fmt.max_facility, fmt.max_card),
                   (fmt.max_facility // 2, fmt.max_card // 3)]:
        raw = fmt.encode(fc, cn)
        d = fmt.decode(raw)
        assert d.facility_code == fc
        assert d.card_number == cn
        assert d.parity_ok


@pytest.mark.parametrize("fmt", ALL_FORMATS, ids=lambda f: f.name)
def test_frame_width(fmt):
    # data + 2 parity bits must equal the declared width
    assert fmt.data_bits + 2 == fmt.total_bits


def test_parity_detects_corruption():
    fmt = get_format("H10301-26")
    raw = fmt.encode(12, 3456)
    # flip a data bit -> parity should now fail
    corrupted = raw ^ (1 << 5)
    assert fmt.decode(raw).parity_ok
    assert not fmt.decode(corrupted).parity_ok


def test_out_of_range_rejected():
    fmt = get_format("H10301-26")
    with pytest.raises(ValueError):
        fmt.encode(fmt.max_facility + 1, 0)
    with pytest.raises(ValueError):
        fmt.encode(0, fmt.max_card + 1)


def test_unknown_format():
    with pytest.raises(KeyError):
        get_format("does-not-exist")


def test_h10306_and_n10002_are_structural_aliases():
    # Both are 16-bit facility + 16-bit card with the same parity; they must
    # encode identically for every value.
    a, b = get_format("H10306-34"), get_format("N10002-34")
    for fc, cn in [(0, 0), (1, 1), (1234, 56789), (65535, 65535)]:
        assert a.encode(fc, cn) == b.encode(fc, cn)


def test_proxmark_aligned_formats_are_flagged():
    # Every registered format is aligned to the Proxmark3 reference layout.
    assert all(f.proxmark_compatible for f in ALL_FORMATS)


def test_layout_string_is_descriptive():
    f = get_format("H10301-26")
    s = f.layout_str()
    assert "card@1:16" in s and "facility@17:8" in s and "P0=odd" in s
