"""MS-XCA examples, format edge cases, and optional native Windows checks."""

import ctypes
import os
from pathlib import Path
import random
import sys

import pytest

from hex_editor.transform_ops.xpress_huffman import MAX_OUTPUT_SIZE, decompress
from hex_editor.transforms import RecipeStep, TransformError, apply_recipe, find_spec


def abc_stream(length=300):
    # MS-XCA 3.2 example: abc + distance-3 match + EOF.
    header = bytearray(256)
    header[48], header[49], header[128], header[143] = 0x30, 0x23, 2, 0x20
    match = length - 6
    if match < 270:
        extension = bytes([match - 15])
    elif match <= 65535:
        extension = b'\xff' + match.to_bytes(2, 'little')
    else:
        extension = b'\xff\0\0' + match.to_bytes(4, 'little')
    return bytes(header) + bytes.fromhex('a8 dc 00 00') + extension


def literal_block(symbols):
    # A complete canonical alphabet with all 512 symbols at width 9.
    bits = ''.join(f'{symbol:09b}' for symbol in symbols)
    bits += '0' * (-len(bits) % 16 + 16)
    payload = b''.join(int(bits[i:i+16], 2).to_bytes(2, 'little')
                       for i in range(0, len(bits), 16))
    return b'\x99' * 256 + payload


def test_microsoft_alphabet_example():
    header = bytearray(256)
    header[48:62] = bytes.fromhex('50 55 55 55 55 55 55 55 55 55 55 45 44 04')
    header[128] = 4
    payload = bytes.fromhex('d8 52 3e d7 94 11 5b e9 19 5f f9 d6 7c df 8d 04 00 00 00 00')
    assert decompress(bytes(header) + payload, 26) == b'abcdefghijklmnopqrstuvwxyz'


@pytest.mark.parametrize('size', [24, 273, 300, 65535, 65536, 65537, 196608])
def test_match_lengths_overlap_and_cross_block_boundary(size):
    expected = (b'abc' * ((size + 2) // 3))[:size]
    assert decompress(abc_stream(size), size) == expected


def test_multiple_blocks_and_cross_block_history():
    first = bytes(range(256)) * 256
    # Symbol 256 is a match, even if all compressed bytes are already buffered.
    second = [256, ord('!'), 256]
    raw = literal_block(first) + literal_block(second)
    assert decompress(raw, 65540) == first + b'\xff\xff\xff!'


def test_256_is_a_match_not_an_unconditional_end_marker():
    raw = literal_block([65, 256, 66, 256])
    assert decompress(raw, 5) == b'AAAAB'


def test_empty_stream():
    assert decompress(b'', 0) == b''
    with pytest.raises(TransformError, match='positive Expected size'):
        decompress(abc_stream(), 0)


@pytest.mark.parametrize('size', [-1, True, 1.5, '300'])
def test_invalid_size(size):
    with pytest.raises(TransformError, match='non-negative integer'):
        decompress(b'', size)


def test_all_truncations_of_extended_length_example():
    raw = abc_stream()
    for count in range(len(raw)):
        with pytest.raises(TransformError, match='truncated'):
            decompress(raw[:count], 300)


@pytest.mark.parametrize('table', [b'\0' * 256, b'\x11' * 256, b'\xff' * 256])
def test_invalid_huffman_tables(table):
    with pytest.raises(TransformError, match='Huffman table'):
        decompress(table + b'\0' * 8, 1)


def test_invalid_back_reference():
    with pytest.raises(TransformError, match='before the start'):
        decompress(literal_block([256]), 3)


def test_invalid_extended_length():
    with pytest.raises(TransformError, match='invalid extended match length'):
        decompress(abc_stream()[:-2] + b'\x0e\0', 300)


def test_match_cannot_exceed_expected_output():
    with pytest.raises(TransformError, match='exceeds Expected size'):
        decompress(abc_stream(), 299)


def test_bomb_output_limit_is_checked_before_allocation():
    with pytest.raises(TransformError, match='output exceeds'):
        decompress(abc_stream(MAX_OUTPUT_SIZE + 1), MAX_OUTPUT_SIZE + 1)
    with pytest.raises(TransformError, match='exceeds Expected size'):
        decompress(abc_stream(0xFFFFFFFF), 300)


def test_time_budget_is_enforced_during_match_expansion(monkeypatch):
    import hex_editor.transform_ops.xpress_huffman as codec
    clock = iter([0, 0, 0, 3])  # deadline, block, first symbol, long match copy
    monkeypatch.setattr(codec, 'monotonic', lambda: next(clock))
    with pytest.raises(TransformError, match='time limit'):
        decompress(abc_stream(), 300)


def test_mutated_and_random_streams_remain_bounded():
    rng = random.Random(405)
    raw = abc_stream()
    for _ in range(400):
        data = bytearray(raw)
        for _ in range(rng.randrange(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            result = decompress(bytes(data), 300, time_limit=.1)
        except TransformError:
            pass
        else:
            assert len(result) == 300


@pytest.mark.parametrize('size', ['300', '0x12c', '0300', 300])
def test_registered_recipe_and_size_parsing(size):
    spec = find_spec('XPRESS Huffman decompress')
    assert spec.category == 'Compression'
    assert spec.requires_full_input and not spec.length_preserving
    assert apply_recipe(abc_stream(), [RecipeStep(spec.name, {'expected_size': size})]) == b'abc' * 100


@pytest.mark.parametrize('params', [{}, {'expected_size': ''}, {'expected_size': 'abc'}, {'expected_size': '3.5'}])
def test_recipe_requires_original_size(params):
    with pytest.raises(TransformError, match='enter Expected size'):
        apply_recipe(abc_stream(), [RecipeStep('XPRESS Huffman decompress', params)])


@pytest.mark.skipif(not os.getenv('XPRESS_TEST_CORPUS'), reason='optional Windows-generated Samba corpus')
def test_windows_generated_corpus():
    root = Path(os.environ['XPRESS_TEST_CORPUS'])
    count = 0
    for directory in ('compressed-huffman', 'compressed-more-huffman'):
        for path in sorted((root / directory).glob('*.lzhuff')):
            original = (root / 'decompressed' / (path.stem + '.decomp')).read_bytes()
            assert decompress(path.read_bytes(), len(original)) == original, path.name
            count += 1
    assert count >= 100


@pytest.mark.skipif(sys.platform != 'win32', reason='requires Windows ntdll')
def test_native_rtl_compression_and_decompression():
    """Compare actual RtlDecompressBufferEx output on Windows test runners."""
    dll = ctypes.WinDLL('ntdll')
    u16, u32, ptr = ctypes.c_uint16, ctypes.c_uint32, ctypes.c_void_p
    query = dll.RtlGetCompressionWorkSpaceSize
    query.argtypes = [u16, ctypes.POINTER(u32), ctypes.POINTER(u32)]
    query.restype = ctypes.c_int32
    compress = dll.RtlCompressBuffer
    compress.argtypes = [u16, ptr, u32, ptr, u32, u32, ctypes.POINTER(u32), ptr]
    compress.restype = ctypes.c_int32
    decode = dll.RtlDecompressBufferEx
    decode.argtypes = [u16, ptr, u32, ptr, u32, ctypes.POINTER(u32), ptr]
    decode.restype = ctypes.c_int32
    workspace_size, fragment_size = u32(), u32()
    assert query(4, ctypes.byref(workspace_size), ctypes.byref(fragment_size)) == 0
    workspace = ctypes.create_string_buffer(max(workspace_size.value, fragment_size.value))
    for original in (b'abc' * 100, b'\0' * 196608, bytes(range(256)) * 1025):
        src = ctypes.create_string_buffer(original)
        compressed = ctypes.create_string_buffer(len(original) * 2 + 1024)
        size = u32()
        assert compress(4, src, len(original), compressed, len(compressed), 4096,
                        ctypes.byref(size), workspace) == 0
        output = ctypes.create_string_buffer(len(original))
        decoded_size = u32()
        assert decode(4, output, len(output), compressed, size.value,
                      ctypes.byref(decoded_size), workspace) == 0
        assert output.raw[:decoded_size.value] == original
        assert decompress(compressed.raw[:size.value], len(original)) == original
