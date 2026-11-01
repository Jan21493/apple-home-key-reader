import sys

# Für NTAG 2xx Karten – Standard Schreibzugriff
#
"""


"""
import nfc
import nfc.tag
import binascii

KEY_A = bytes.fromhex("FFFFFFFFFFFF")
BLOCK = 0
DATA  = b"HELLO NFCpy DEMO".ljust(16, b"\x00")[:16]


def calculate_xor_checksum(data):
    """Berechnet die XOR-Summe über alle Bytes in 'data'."""
    checksum = 0
    for byte in data:
        checksum ^= byte
    return checksum


def on_connect(tag):
    print("Tag gefunden:", tag)

    print("tag.product:", getattr(tag, "product", None))

    if tag.type != "Type2Tag":
        print("Not a Type2Tag")
        return False

    # Page 3 lesen (Capability Container)
    cc = tag.read(3)  # 4 bytes: CC0..CC3
    print("CC:", cc.hex())

    mem_size_units = cc[2]          # in "8-byte blocks"
    total_bytes = mem_size_units * 8
    print("CC memory size units:", mem_size_units, "=> total bytes:", total_bytes)

    # Nutzdaten-Kapazität ist i.d.R. kleiner als total_bytes (wegen Header/Lock/OTP),
    # aber total_bytes reicht meist zum Unterscheiden 213/215/216.
    # Typische CC[2] Werte:
    # - NTAG213: 0x12
    # - NTAG215: 0x3E
    # - NTAG216: 0x6D
    guess = {0x12: "NTAG213", 0x3E: "NTAG215", 0x6D: "NTAG216"}.get(mem_size_units)
    print("guess:", guess or "unknown (not a standard NTAG21x CC size)")

    return False


    page0 = tag.read(0)
    page1 = tag.read(1)
    page2 = tag.read(2)

    # 3. BCC0 berechnen: 0x88 wird ergänzt
    bcc0 = calculate_xor_checksum(bytes([0x88]) + page0[0:3])
    bcc1 = calculate_xor_checksum(page1[0:4])

    print("Read existing UID: ", page0[0:3].hex().upper(), page1[0:4].hex().upper())
    print("Page 0:", page0.hex().upper(), "UID0, UID1, UID2, BCC0 - calculated:", f"{bcc0:02X}")
    print("Page 1:", page1.hex().upper(), "UID3, UID4, UID5, UID6 - calculated:", f"{bcc1:02X}")
    print("Page 2:", page2.hex().upper(), "BCC1, Internal, Lock...")
    print("")


    # 1. Neue UID definieren (4 Bytes)
    new_uid = bytes.fromhex("00AFFE00BADE00") # Beispiel: Neue 7-Byte UID: 00 AF FE 00 BA DE 00

    page0[0:3] = new_uid[0:3]  # UID0, UID1, UID2
    page0[3] = calculate_xor_checksum(bytes([0x88]) + new_uid[0:3]) # BCC0
    page1[0:4] = new_uid[3:7]  # UID3, UID4, UID5, UID6
    page2[0] = calculate_xor_checksum(new_uid[3:7])  # BCC1

    # 3. BCC0 berechnen: 0x88 wird ergänzt
    bcc0 = calculate_xor_checksum(bytes([0x88]) + page0[0:3])
    bcc1 = calculate_xor_checksum(page1[0:4])


    print("Versuche nun Page 0 zu schreiben...")
    print("Write new UID: ", page0[0:3].hex().upper(), page1[0:4].hex().upper())
    print("Page 0:", page0.hex().upper(), "UID0, UID1, UID2, BCC0 - calculated:", f"{bcc0:02X}")
    print("Page 1:", page1.hex().upper(), "UID3, UID4, UID5, UID6 - calculated:", f"{bcc1:02X}")
    print("Page 2:", page2.hex().upper(), "BCC1, Internal, Lock...")
    print("...")

    # 4. Neue Pages schreiben
    try:
        tag.write(0, page0[0:4])
        print("Wrote Page 0")
        tag.write(1, page1[0:4])
        print("Wrote Page 1")
        tag.write(2, page2[0:4])
        print("Wrote Page 2")
        print("UID erfolgreich geschrieben!")
    except Exception as e:
        print(f"Fehler beim Schreiben: {e}")
    return True

with nfc.ContactlessFrontend('tty:ttyUSB0:pn532') as clf:
    print("Bitte NTAG 2xx auflegen...")
    clf.connect(rdwr={'on-connect': on_connect})

print("Vorgang beendet.")
