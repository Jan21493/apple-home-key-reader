import nfc.tag
import nfc.tag.tt1
import nfc.tag.tt1_broadcom
import nfc.tag.tt2
import nfc.tag.tt2_nxp
import nfc.tag.tt3
import nfc.tag.tt3_sony
import nfc.tag.tt4
import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional
import json

logger = logging.getLogger(__name__)

@dataclass
class RF_Info:
    id: int                 # Unique integer ID for the card type
    nfcClass: str           # NFCpy Tag class name as string
    uid_len: int            # 4, 7, or 10 byte (10-byte UID is rare, so it's not used here yet)
    atqa: Optional[int]     # None means: atqa is not relevant for identification
    sak: int
                            # DESFire, Ultralight, NTAG, but not for Classic or Plus in SL0/1 mode
    description: str

class TagTypeID(Enum):
    """
    Class to get a unique card type ID for a specific instance of a Tag class based on internal tests done in NFCPy
    
    NFCPy saves this information in Tag.TYPE and Tag._product (only for some card types) as strings. 
    It is used e.g. with Tag.identifier for printing an instance with __str__

    This enum provides a unique integer ID for each card/tag type and product known to NFCPy.
    It can be used for easier comparison and identification of card/tag types.
    """

    """
   ↳ Class: Type1Tag (Tag)  ID = 1000
      ↳ Class: Topaz (Type1Tag)  ID = 1100
      ↳ Class: Topaz512 (Type1Tag)  ID = 1200
    ↳ Class: Type2Tag (Tag)  ID = 2000
      ↳ Class: MifareUltralight (Type2Tag)  ID = 2100
      ↳ Class: MifareUltralightC (Type2Tag)  ID = 2200
      ↳ Class: NTAG203 (Type2Tag)  ID = 2300
      ↳ Class: NTAG21x (Type2Tag)  ID = 2400
        ↳ Class: NTAG210 (NTAG21x)  ID = 2410
        ↳ Class: NTAG212 (NTAG21x)  ID = 2420
        ↳ Class: NTAG213 (NTAG21x)  ID = 2430
        ↳ Class: NTAG215 (NTAG21x)  ID = 2440
        ↳ Class: NTAG216 (NTAG21x)  ID = 2450
        ↳ Class: MifareUltralightEV1 (NTAG21x)  ID = 2460
          ↳ Class: MF0UL11 (MifareUltralightEV1)  ID = 2461
          ↳ Class: MF0ULH11 (MifareUltralightEV1)  ID = 2462
          ↳ Class: MF0UL21 (MifareUltralightEV1)  ID = 2463
          ↳ Class: MF0ULH21 (MifareUltralightEV1)  ID = 2464
      ↳ Class: NTAGI2C (Type2Tag)  ID = 2500
        ↳ Class: NT3H1101 (NTAGI2C)  ID = 2510
        ↳ Class: NT3H1201 (NTAGI2C)  ID = 2520
    ↳ Class: Type3Tag (Tag)  ID = 3000
      ↳ Class: FelicaStandard (Type3Tag)  ID = 3100
        ↳ Class: FelicaMobile (FelicaStandard)  ID = 3110
      ↳ Class: FelicaLite (Type3Tag)  ID = 3200
        ↳ Class: FelicaLiteS (FelicaLite)  ID = 3210
      ↳ Class: FelicaPlug (Type3Tag)  ID = 3300
    ↳ Class: Type4Tag (Tag)  ID = 4000
      ↳ Class: Type4ATag (Type4Tag)  ID = 4100
      ↳ Class: Type4BTag (Type4Tag)  ID = 4200
    """

    UNKNOWN             = RF_Info("Unknown", 00, 0, 0xFFFF, 0xFF, "Unknown card type")

    #

    # MIFARE Classic Series: DOES NOT support GetVersion, UID is 4 Byte, but can be 7 Byte as well)
    MINI                     = RF_Info(10, "Type2Tag", 4, 0x0004, 0x09, "MIFARE mini")
    CLASSIC_1K               = RF_Info(11, "Type2Tag", 4, 0x0004, 0x08, "MIFARE Classic 1K or Plus S/X/SE in SL0/1 mode (Classic compatibility) with 4-byte UID")
    CLASSIC_2K               = RF_Info(12, "Type2Tag", 4, 0x0004, 0x19, "MIFARE Classic 2K with 4-byte UID")
    CLASSIC_4K               = RF_Info(13, "Type2Tag", 4, 0x0004, 0x18, "MIFARE Classic 4K or Plus S/X in SL0/1 mode (Classic compatibility) with 4-byte UID")
    CLASSIC_1K_7B            = RF_Info(14, "Type2Tag", 7, 0x0002, 0x08, "MIFARE Classic 1K or Plus S/X/SE in SL1 mode (Classic compatibility) with 7-byte UID")
    CLASSIC_2K_7B            = RF_Info(15, "Type2Tag", 7, 0x0002, 0x19, "MIFARE Classic 2K or Plus S/X in SL1 mode (Classic compatibility) with 7-byte UID")
    CLASSIC_4K_7B            = RF_Info(16, "Type2Tag", 7, 0x0002, 0x18, "MIFARE Classic 4K or Plus S/X in SL1 mode (Classic compatibility) with 7-byte UID")
    
    # Ultralight / NTAG Family (Type 2 Tags): support GetVersion (except very old Ultralight cards)
    ULTRALIGHT_MF0UL11_7B    = RF_Info(21, "MF0UL11", 7, 0x0044, 0x00, "MIFARE Ultralight EV1 48B (MF0UL11) with 7-byte UID")
    ULTRALIGHT_MF0ULH11_7B   = RF_Info(22, "MF0ULH11", 7, 0x0044, 0x00, "MIFARE Ultralight EV1 48B (MF0ULH11) with 7-byte UID")
    ULTRALIGHT_MF0UL21_7B    = RF_Info(23, "MF0UL21", 7, 0x0044, 0x00, "MIFARE Ultralight EV1 128B (MF0UL21) with 7-byte UID")
    ULTRALIGHT_MF0ULH21_7B   = RF_Info(24, "MF0ULH21", 7, 0x0044, 0x00, "MIFARE Ultralight EV1 128B (MF0ULH21) with 7-byte UID")


    NTAG5                    = RF_Info(25, "NTAG5XXX", 7, 0x0344, 0x00, "NTAG 5") # to be tested
    SHELL_RECHARGE_CARD      = RF_Info(26, "MifareUltralight", 7, 0x0044, 0x08, "Shell Recharge card with 7-byte real UID")

    Type2Tag                 = RF_Info(30, "Type2Tag", 7, 0x0044, 0x00, "NTAG 21x generic")
    NTAG_215                 = RF_Info(31, "NTAG215", 7, 0x0044, 0x00, "NTAG 215 504B")
    NTAG_216                 = RF_Info(32, "NTAG216", 7, 0x0044, 0x00, "NTAG 216 888B")



    # DESFire Family / NTAG DNA High Security & DNA Family (Type 4 Tags / ISO-DEP): support GetVersion by ISO-DEP with Layer 4 (extended information)
    # additional distinguisher is ATQA with following possible values seen in the field:
    #   0x0344 for DESFire EV1 cards with 7-byte real UID
    #   0x0304 for DESFire EVx cards with 4-byte random UID
    #   0x0044 for Banking cards with 7-byte real UID - tested with a Visa Debit Card, comdirect Bank AG from 2025
    #   0x0004 for Apple Mobile with 4-byte random UID - tested with an Apple iPhone 14, does NOT support GetVersion command
    #   0x0004 for German Helth Insurance Card (Gesundheitskarte) with 4-byte random UID - tested with a card from 2023, does NOT support GetVersion command
    #   0x0008 for German ID card (Personalausweis) with 4-byte random UID - tested with a card from 2024, does NOT support GetVersion command
    #   0x0048 for Tesla Key Cardd with 7-byte real UID - tested with a Tesla Model 3 Key Card from 2022, does NOT support GetVersion command

    # you may add more entries here as needed, order matters (first match), so more specific entries should be listed first!
    #
    # NOTE: This might be helpful for identification with your own cards if they have a 7-byte real UIDs, but unknown keys, 
    #       e.g. banking cards, Tesla key cards, etc. (as long as they are unique).
    #       The attribute 'modern' should be set to false if that card/tag does NOT support GetVersion command and you want to
    #       avoid trying to send that command to it.
    #
    # IMPORTANT: The security based on UID is weak and adding specific values for ATQA and SAK may not improve security significantly.
    #            It is recommended to use GetVersion (0x60) command and your own encryption keys for security-sensitive applications.
    #            Adding entries to this list is optional and mainly for convenience in identifying card types.
    APPLE_MOBILE        = RF_Info(50, "Type4ATag", 4, 0x0004, 0x20, "Apple mobile phone with Home Key (NFC Type 4 Tag)") # this entry should prevent cards with same SAK/ATQA from being misidentified as DESFire
    TESLA_KEY_CARD      = RF_Info(51, "Type4ATag", 7, 0x0048, 0x20, "Tesla key card with 7-byte real UID")
    BANKING_CARD        = RF_Info(52, "Type4ATag", 7, 0x0044, 0x20, "Banking card (e.g., Visa Debit/Credit) with 7-byte real UID")
    IDENTITY_CARD       = RF_Info(53, "Type4ATag", 7, 0x0008, 0x20, "Identity card with 4-byte random UID")

    # Generic entries for MIFARE DESFire Family, Plus in SL3 mode, NTAG 4xx, or X DNA that support further identification by GetVersion (0x60) command
    DESFIRE_PLUS_NTAG4  = RF_Info(30, "Type4ATag", 7, None, 0x20, "MIFARE DESFire Family, Plus in SL3 mode, NTAG 4xx, or X DNA with 7-byte UID")
    DESFIRE_PLUS_4B     = RF_Info(31, "Type4ATag", 4, None, 0x20, "MIFARE DESFire Family, Plus in SL3 mode, NTAG 4xx, or X DNA with 4-byte random UID")

    # MIFARE Plus: support GetVersion, but only with SL0 (for unambiguous identification) and SL3
    PLUS_S_SL3_2K_7B    = RF_Info(40, "Type4ATag", 7, 0x0344, 0x10, "MIFARE Plus S/X with 2K in SL2 mode (hybrid security)") # Security Level 2
    PLUS_S_SL3_2K_4B    = RF_Info(41, "Type4ATag", 4, 0x0344, 0x10, "MIFARE Plus S/X with 2K in SL2 mode (hybrid security)") # Security Level 2
    PLUS_S_SL3_4K_7B    = RF_Info(42, "Type4ATag", 7, 0x0344, 0x11, "MIFARE Plus S/X with 4K in SL2 mode (hybrid security)") # Security Level 2
    PLUS_S_SL3_4K_4B    = RF_Info(43, "Type4ATag", 4, 0x0344, 0x11, "MIFARE Plus S/X with 4K in SL2 mode (hybrid security)") # Security Level 2


    @classmethod
    def identify(cls, uid: bytes(), atqa: int, sak: int) -> 'TagTypeID':
        """
        Returns matching card type to RF-params 
        
        Identifies potential card types based on RF parameters (UID, ATQA, SAK) as a first step
        """
    
        logger.debug(f"identify_by_rf called: uid_len: {len(uid)}, atqa: {hex(atqa)}, sak: {hex(sak)}")
        card_type = TagTypeID.UNKNOWN  # Return UNKNOWN if no match found
        uid_len = len(uid)
        for card in cls:
            if (card.value.uid_len == uid_len and 
                card.value.sak == sak):
                if card.value.atqa is None:
                    card_type = card
                    break
                elif card.value.atqa == atqa:
                    card_type = card
                    break
        
        # additional verification of 1st byte of UID
        if card_type == TagTypeID.UNKNOWN:
            logger.debug("No matching card type found.")
        else:
            logger.debug(f"Matching card type found: {card_type.name} - {card_type.value.description}")
        return card_type

    def fingerprint(cls, uid_len: int, atqa: int, sak: int) -> 'TagTypeID':
        """
        Returns matching card type to RF-params 
        
        Identifies potential card types based on RF parameters (UID, ATQA, SAK) as a first step
        """
    
        logger.debug(f"fingerprint called: uid_len: {uid_len}, atqa: {hex(atqa)}, sak: {hex(sak)}")
        card_type = TagTypeID.UNKNOWN  # Return UNKNOWN if no match found
        for card in cls:
            if (card.value.uid_len == uid_len and 
                card.value.sak == sak):
                if card.value.atqa is None:
                    card_type = card
                    break
                elif card.value.atqa == atqa:
                    card_type = card
                    break
        return card_type

    # By default, files that contain configuration, signatures and own cards are located in the same folder as the project
    CARDSIGNATURES_FILE_PATH = "cardsignatures.json"

    def save_cardsignatures(cls,path=CARDSIGNATURES_FILE_PATH) -> dict:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(cls, f, ensure_ascii=False, indent=4)
        return

    @classmethod
    def save_cardsignatures(cls, path: str = CARDSIGNATURES_FILE_PATH) -> None:
        """Save card signatures to a JSON file."""
        try:
            # Convert TagTypeID enum data to a serializable dictionary
            data_to_save = {tag.name: tag.value.__dict__ for tag in cls}
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, ensure_ascii=False, indent=4)
            logger.debug(f"Card signatures saved to {path}")
        except Exception as e:
            logger.error(f"Failed to save card signatures: {e}")

    @classmethod
    def load_cardsignatures(cls, path: str = CARDSIGNATURES_FILE_PATH) -> Dict[str, RF_Info]:
        """Load card signatures from a JSON file or fallback to defaults."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Parse data into a dictionary of RF_Info objects
                loaded_signatures = {name: RF_Info(**info) for name, info in data.items()}
                logger.debug(f"Card signatures loaded from {path}")
                return loaded_signatures
        except FileNotFoundError:
            # File not found, fallback to defaults
            logger.warning(f"File {path} not found. Using default card signatures.")
            return {tag.name: tag.value for tag in cls}
        except Exception as e:
            logger.error(f"Failed to load card signatures: {e}")
            return {tag.name: tag.value for tag in cls}

# Die vier Basis-Tag-Typen des NFC Forums
base_types = [
    nfc.tag.Tag,
]



def show_hierarchy(cls, parentCls, level=0, baseNo=1, id=0):
    indent = "  " * level
    # 'type' ist das offizielle NFC Forum Label, '__name__' der Python-Klassenname
    # '_product' ist oft als Klassenattribut für spezialisierte Chips hinterlegt

    name = cls.__name__
    parentName = parentCls.__name__ if parentCls else 'N/A'

    # print(f"baseNo: {baseNo}, level: {level}")

    if level == 0:
        print(f" Base Class: {name}  ID =", id)
    else:
        id += baseNo * (10 ** (4-level))
        print(f"{indent}  ↳ Class: {name} ({parentName})  ID =", id)

    # Rekursiv alle Subklassen (Spezialisierungen) finden
    baseNo = 1
    for subclass in cls.__subclasses__():
        show_hierarchy(subclass, cls, level + 1, baseNo, id)
        baseNo  += 1

print("nfcpy Tag hierarchy overview:\n")
for base in base_types:
    show_hierarchy(base, None)

