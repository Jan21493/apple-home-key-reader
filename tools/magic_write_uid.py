# Für Gen2 Karten (CUID) – Standard Schreibzugriff
# Diese Karten benötigen keine Unlock-Sequenz. Sie müssen sich lediglich mit dem Key (meist der Standard-Key FFFFFFFFFFFF) authentifizieren.
#
"""
nfc-mfclassic r a u mycard.mfd
echo "033C1CE5C60804006263646566676869" | xxd -r -p > block0.mfd
sudo nfc-mfclassic w a f block0.mfd

"""
import nfc
import nfc.tag
import binascii

KEY_A = bytes.fromhex("FFFFFFFFFFFF")
BLOCK = 0
DATA  = b"HELLO NFCpy DEMO".ljust(16, b"\x00")[:16]

def calculate_bcc(uid_hex):
    # Berechnet das BCC (XOR Verknüpfung der 4 UID Bytes)
    uid_bytes = binascii.unhexlify(uid_hex)
    bcc = 0
    for b in uid_bytes:
        bcc ^= b
    return bcc

def on_connect(tag):
    print("Tag gefunden:", tag)

    print("tag.product:", getattr(tag, "product", None))


    # 1. Neue UID definieren (4 Bytes)
    new_uid = "ABCDEF12" 
    new_uid = "033C1CE5" # elbFitness 
    bcc = format(calculate_bcc(new_uid), '02X')
    
    # 2. Block 0 Daten zusammenbauen (16 Bytes)
    # Aufbau: UID (4B) + BCC (1B) + SAK (1B) + ATQA (2B) + Restliche Herstellerdaten (8B)
    # ACHTUNG: SAK/ATQA müssen zum Kartentyp passen (hier Classic 1K)
    block0_data = binascii.unhexlify(new_uid + bcc + "080400" + "6263646566676869")

    print("Befehl: sudo nfc-mfclassic W a B0 ", KEY_A, block0_data.hex())
    return
    # 3. Authentifizierung an Sektor 0 mit Key A
    try:
        ok = tag.authenticate(BLOCK, [0x60], KEY_A)
        print("authenticate(BLOCK, [0x60], KEY_A) ->", ok)
        return
        if ok:
             # 4. Block 0 schreiben
            if tag.write(BLOCK, block0_data):
                print("UID erfolgreich geändert!")
            else:
                print("Fehler beim Schreiben des Blocks.")
            # 5. Block 0 lesen zum Verifizieren
            print("read   :", tag.read(BLOCK).hex())
            return True
        else:
            print("Authentifizierung fehlgeschlagen. Falscher Key?")
            return False    
    except TypeError as e:
        print("authenticate(block, key) passt nicht:", e)
        print("read   :", tag.read(BLOCK).hex())
        print("Konnte nicht authentifizieren – vermutlich kein MIFARE Classic oder andere API.")
    return False

with nfc.ContactlessFrontend('tty:ttyUSB0:pn532') as clf:
    print("Bitte Magic Card (Gen2) auflegen...")
    clf.connect(rdwr={'on-connect': on_connect})

print("Vorgang beendet.")