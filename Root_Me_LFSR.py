import binascii

# Signature PNG (8 octets)
png_header = bytes.fromhex("89504E470D0A1A0A")

# lire fichier encrypté
with open("challenge.png.encrypt", "rb") as f:
    encrypted = f.read()

# récupérer le keystream initial (8 octets)
keystream_start = bytes([encrypted[i] ^ png_header[i] for i in range(8)])
print("Keystream start (bytes):", keystream_start)
print("Keystream start (hex):", keystream_start.hex())

# bytes -> bits (MSB first)
bits = []
for byte in keystream_start:
    for i in range(8):
        bits.append((byte >> (7 - i)) & 1)

print("First bits:", bits)

def berlekamp_massey(s):
    """
    Berlekamp–Massey over GF(2)
    Returns (L, C) where:
      - L is linear complexity (degree)
      - C is connection polynomial coefficients [c0, c1, ..., cL] with c0 = 1
    Recurrence:
      s[n] = c1*s[n-1] XOR c2*s[n-2] XOR ... XOR cL*s[n-L]
    """
    n = len(s)
    C = [0] * n
    B = [0] * n
    C[0] = 1
    B[0] = 1
    L = 0
    m = -1

    for i in range(n):
        # discrepancy d
        d = s[i]
        for j in range(1, L + 1):
            d ^= C[j] & s[i - j]

        if d == 1:
            T = C.copy()
            shift = i - m
            # C(x) = C(x) + x^shift * B(x)
            for j in range(0, n - shift):
                C[j + shift] ^= B[j]
            if 2 * L <= i:
                L = i + 1 - L
                m = i
                B = T

    return L, C[:L + 1]

L, C = berlekamp_massey(bits)
print("Degree (L):", L)
print("Connection polynomial C:", C)

def generate_bits_from_recurrence(initial_bits, C, total_len):
    """
    Generate bits using recurrence defined by C.
    initial_bits must contain at least L bits.
    """
    L = len(C) - 1
    if len(initial_bits) < L:
        raise ValueError(f"Need at least {L} initial bits, got {len(initial_bits)}")

    out = initial_bits[:]
    for i in range(len(out), total_len):
        nxt = 0
        # s[i] = XOR_{j=1..L} C[j] * s[i-j]
        for j in range(1, L + 1):
            if C[j]:
                nxt ^= out[i - j]
        out.append(nxt)
    return out[:total_len]

def bits_to_bytes(bitlist):
    if len(bitlist) % 8 != 0:
        raise ValueError("bitlist length must be multiple of 8")
    res = bytearray()
    for i in range(0, len(bitlist), 8):
        b = 0
        for k in range(8):
            b = (b << 1) | bitlist[i + k]
        res.append(b)
    return bytes(res)

# Longueur totale de keystream requise (en bits)
total_bits = 8 * len(encrypted)

# Générer le keystream complet (en bits), puis en bytes
# On utilise comme "initial_bits" les premiers bits connus (bits)
full_keystream_bits = generate_bits_from_recurrence(bits, C, total_bits)
full_keystream = bits_to_bytes(full_keystream_bits)

# Déchiffrement
decrypted = bytes([encrypted[i] ^ full_keystream[i] for i in range(len(encrypted))])

with open("recovered.png", "wb") as f:
    f.write(decrypted)

print("Recovered written to recovered.png")
