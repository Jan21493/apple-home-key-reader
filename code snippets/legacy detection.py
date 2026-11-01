from enum import Enum
from dataclasses import dataclass

@dataclass
class RF_Info:
    id: int
    uid_len: int                # 4, 7 or 10 byte
    atqa: str                   # Hex-String, e.g. "0004"
    sak: str                    # Hex-String, e.g. "08"
    supports_get_version: bool  # indicates if command 0x60 GetVersion is supported
    description: str

class RF_Identification(Enum):
    # UNKNOWN Card Type
    UNKNOWN             = RF_Info(00, 0, 0xFFFF, 0xFF, False, "Unknown card type")
    # MIFARE Classic Series: DOES NOT support GetVersion, UID is 4 Byte, but can be 7 Byte as well)
    MINI                = RF_Info(10, 4, 0x0004, 0x09, False, "MIFARE mini")
    CLASSIC_1K          = RF_Info(11, 4, 0x0004, 0x08, False, "MIFARE Classic 1K or Plus S/X in SL0/1 mode (Classic compatibility) with 4-byte UID")
    CLASSIC_2K          = RF_Info(12, 4, 0x0004, 0x19, False, "MIFARE Classic 2K or Plus S/X in SL0/1 mode (Classic compatibility) with 4-byte UID")
    CLASSIC_4K          = RF_Info(13, 4, 0x0004, 0x18, False, "MIFARE Classic 4K or Plus S/X in SL0/1 mode (Classic compatibility) with 4-byte UID")
    CLASSIC_1K_7B       = RF_Info(14, 7, 0x0002, 0x08, False, "MIFARE Classic 1K or Plus S/X in SL1 mode (Classic compatibility) with 7-byte UID")
    CLASSIC_2K_7B       = RF_Info(15, 7, 0x0002, 0x19, False, "MIFARE Classic 2K or Plus S/X in SL1 mode (Classic compatibility) with 7-byte UID")
    CLASSIC_4K_7B       = RF_Info(16, 7, 0x0002, 0x18, False, "MIFARE Classic 4K or Plus S/X in SL1 mode (Classic compatibility) with 7-byte UID")
    
    # Ultralight / NTAG Family (Type 2 Tags): support GetVersion (except very old Ultralight cards)
    ULTRALIGHT_NTAG2_4B = RF_Info(20, 4, 0x0044, 0x00, True, "MIFARE Ultralight Series, NTAG 2xx mit 4-byte UID")
    ULTRALIGHT_NTAG2_7B = RF_Info(21, 7, 0x0044, 0x00, True, "MIFARE Ultralight Series, NTAG 2xx, I2C, or I2C Plus mit 7-byte UID")
    NTAG5               = RF_Info(22, 7, 0x0344, 0x00, True, "NTAG 5")
 
    # DESFire Family / NTAG DNA High Security & DNA Family (Type 4 Tags / ISO-DEP): support GetVersion by ISO-DEP with Layer 4 (extended information)
    DESFIRE_PLUS_NTAG4  = RF_Info(30, 7, 0x0344, 0x20, True, "MIFARE DESFire Family or Plus in SL3 mode (Full AES mode, Layer 4), or NTAG 4xx or X DNA with 7-byte UID")
    DESFIRE_PLUS_4B     = RF_Info(31, 4, 0x0304, 0x20, True, "MIFARE DESFire Family or Plus in SL3 mode (Full AES mode, Layer 4) with 4-byte random UID")

    # MIFARE Plus: support GetVersion, but only with SL3
    PLUS_S_SL3          = RF_Info(40, 7, 0x0004, 0x11, False, "MIFARE Plus S/X in SL3 mode (AES security)") # Security Level 3
    PLUS_S_SL3          = RF_Info(40, 4, 0x0004, 0x11, False, "MIFARE Plus S/X in SL3 mode (AES security)") # Security Level 3

    # Apple Mobile: does not support GetVersion for identification with Apple Home Key
    APPLE_MOBILE        = RF_Info(50, 4, 0x0004, 0x20, False, "Apple mobile phone with Home Key (NFC Type 4 Tag)")

    @classmethod
    def identify_by_rf(cls, uid_len: int, atqa: int, sak: int) -> list['RF_Identification']:
        """
        Returns matching card type to RF-params
        
        Identifies potential card types based on RF parameters (UID, ATQA, SAK) as a first step
        """

        print("identify_by_rf called: uid_len:", uid_len, "atqa:", hex(atqa), "sak:", hex(sak))
        card_type = RF_Identification.UNKNOWN  # Return UNKNOWN if no match found
        for card in cls:
            if (card.value.uid_len == uid_len and 
                card.value.atqa.lower() == atqa and 
                card.value.sak.lower() == sak):
                card_type = card
                break
        return card_type


# --- Beispiel Logik für deinen Reader 2026 ---

# Simulated scan: an NTAG 213 was detected
uid, atqa, sak = (7, "0044", "00")
legacy_id = RF_Identification.identify_by_rf(uid, atqa, sak)

print(f"Card/tag type based on RF params: {legacy_id.value.description}")
if legacy_id.value.supports_get_version:
    print("Card/tag supports GetVersion (0x60) for detailed hardware info...")
    # Hier würde dein Code für den GetVersion-Befehl folgen
else:
    print("ERROR: Identification finished (no GetVersion possible).")