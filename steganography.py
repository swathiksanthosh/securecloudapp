# steganography.py
# Simple LSB encode/decode for PNG/JPEG using Pillow.
# Stores a UTF-8 message by prefixing 32-bit length (big-endian).

from PIL import Image
import math

def _int_to_bits(n, bits=32):
    return [(n >> i) & 1 for i in reversed(range(bits))]

def _bytes_to_bits(b: bytes):
    for byte in b:
        for i in reversed(range(8)):
            yield (byte >> i) & 1

def _bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)

def capacity_in_bits(img: Image.Image) -> int:
    w, h = img.size
    # using RGB only (3 channels). We manipulate LSB of each channel.
    return w * h * 3

def encode_text_into_image(input_image_path: str, output_image_path: str, message: str):
    """
    Encodes message into image's LSB bits.
    Formats: [32-bit length][message bytes]
    """
    img = Image.open(input_image_path)
    img = img.convert('RGB')
    w, h = img.size
    cap = capacity_in_bits(img)
    data = message.encode('utf-8')
    total_bits = 32 + len(data) * 8
    if total_bits > cap:
        raise ValueError(f"Message too large to hide. Capacity: {cap} bits, need {total_bits} bits")

    bits = []
    # length prefix
    bits.extend(_int_to_bits(len(data), bits=32))
    # message bytes bits
    bits.extend(list(_bytes_to_bits(data)))

    pixels = list(img.getdata())
    new_pixels = []
    bit_idx = 0
    for px in pixels:
        r, g, b = px
        nr, ng, nb = r, g, b
        if bit_idx < total_bits:
            nr = (r & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < total_bits:
            ng = (g & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < total_bits:
            nb = (b & ~1) | bits[bit_idx]; bit_idx += 1
        new_pixels.append((nr, ng, nb))
    out = Image.new('RGB', (w, h))
    out.putdata(new_pixels)
    out.save(output_image_path, format='PNG')

def decode_text_from_image(image_path: str) -> str:
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = list(img.getdata())
    bits = []
    for r, g, b in pixels:
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)
    # first 32 bits => length
    length_bits = bits[:32]
    length = 0
    for bit in length_bits:
        length = (length << 1) | bit
    num_message_bits = length * 8
    message_bits = bits[32:32 + num_message_bits]
    message_bytes = _bits_to_bytes(message_bits)
    return message_bytes.decode('utf-8')
