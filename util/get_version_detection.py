import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from desfire.schemas import CardVersion

log = logging.getLogger(__name__)


@dataclass
class ChipInfo:
    id: int                 # Unique internal index for reference
    hw_type: int            # Hardware type
    hw_sub_type: Optional[int]   # Hardware sub-type for further identification
    hw_major_version: Optional[int]  # Major hardware version number
    hw_minor_version: Optional[int]  # Minor hardware version number
    storage_size: Optional[int]  # None means storage size is irrelevant for identification
    comm_protocol: Optional[int]  # None means communication protocol is irrelevant for identification
    description: str


class MifareNtagType(Enum):
    """
    Identification of tags/cards that support ISO/IEC 14443-4 (layer 4) by GetVersion command
    including MIFARE Ultralight EV1 and AES (not Standard and C!) and NTAG 2xx, I2C plus

    See https://www.nxp.com/docs/en/application-note/AN10833.pdf,
    MIFARE type identification procedure, chapter 2.1 Using GetVersion command
    to exactly identify the ICs.

    Information below shows byte number(s) (starting at 1), meaning, typical values
    Note: all values are in hex!

    After getting a lot of misleading information from e.g. KI, all information here is taken
    from (NXP) application notes and datasheets only. If something is missing or wrong, please
    open an issue or a pull request to fix it.

    See https://www.nxp.com/docs/en/application-note/AN12196.pdf,
    NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints, chapter 5.5. Get Version
    for more information about meaning of bytes in GetVersion response.

    Note: Tags/cards that support ISO/IEC 14443-3 (Layer 3) only, provide this block only.

    Block 1: HW/Product Information
     1 Vendor ID, 0x04 (NXP), not used in the table below
     2 HW/Product Type, see table 1 in AN, e.g. 0x01 (DESFire), 0x04 (NTAG-Family)
     3 HW/Product Sub-Type - used to indicate specific features
     4 Major (HW/Product) Version, e.g., 0x01
     5 Minor (HW/Product) Version, e.g., 0x00
     6 Storage Size, see below
     7 Communication Protocol Type, 0x03 for ISO/IEC 14443-3, 0x05 for ISO/IEC 14443-4

     Notes to Storage Size:
      for Ultralight Family e.g. 0x0B (for 48 Byte) or 0x0E (128 Byte)
   
      Formula: size is byte 6 (Storage size), // means integer division
               if bit 1 = 1, then storageBytes = 2^(size // 2) up to storageBytes = 2^(size // 2 + 1)
               if bit 1 = 0, then storageBytes = 2^(size // 2)
      The least significant bit (bit 1) is used to determine the formula to calculate the storage size.
      The other bits (bits 2 to 8) are used to calculate the actual size in bytes.
   
      As code: if (size & 0x01) then storageBytes = (1 << (size >> 1)) up to storageBytes = (1 << ((size >> 1) + 1))
               if (size & 0x01) == 0x0, then storageBytes = 1 << (size >> 1)

    Note: Tags/cards that support ISO/IEC 14443-4 (Layer 4) provide extended information.

    Block 2: Software (Firmware) Information
    This block has the same structure as Block 1, but refers to the installed firmware (software version) of the chip.
     1 SW Vendor ID, 0x04 (NXP)
     2 SW Type
     3 SW Sub-Type, see above
     4 SW Major Version, e.g., 0x01
     5 SW Minor Version, e.g., 0x01
     6 Storage Size, see above
     7 Protocol Type for Communication protocol, see above
    
    Block 3: Production & Identification Data
     1–7 The 7-byte UID (Unique Identification Number)
     8–11 Production Batch Number (Production Lot)
     12 BatchNo/FabKey
     13 Production Week (Calendar Week) - in hex!
     14 Production Year - in hex!
    """
    # IDENTIFIER                    NO  TYPE  SUBT  HWMAJ HWMIN SIZE  PROT  DESCRIPTION   
    UNKNOWN              = ChipInfo(00, None, None, None, None, None, 0x00, "Unknown card/tag type")

    ULTRALIGHT_EV1_48    = ChipInfo(41, 0x03, 0x01, 0x01, None, 0x0B, 0x03, "MIFARE Ultralight EV1 (V1S) 48B")
    ULTRALIGHT_EV1_128   = ChipInfo(42, 0x03, 0x01, 0x01, None, 0x0E, 0x03, "MIFARE Ultralight EV1 (V1H) 128B")
    ULTRALIGHT_AES_48    = ChipInfo(41, 0x03, 0x01, 0x04, None, 0x0B, 0x03, "MIFARE Ultralight AES (V1S) 48B")
    ULTRALIGHT_AES_128   = ChipInfo(42, 0x03, 0x01, 0x04, None, 0x0E, 0x03, "MIFARE Ultralight AES (V1H) 128B")

    # see https://www.nxp.com/docs/en/application-note/NTAG210_212.pdf
    NTAG_210             = ChipInfo(50, 0x04, 0x01, None, None, 0x0B, 0x03, "NTAG 210 48B")
    NTAG_212             = ChipInfo(51, 0x04, 0x01, None, None, 0x0E, 0x03, "NTAG 212 128B")
    # see https://www.nxp.com/docs/en/application-note/NTAG213_215_216.pdf
    NTAG_213             = ChipInfo(52, 0x04, 0x02, None, None, 0x0F, 0x03, "NTAG 213 144B")
    NTAG_215             = ChipInfo(53, 0x04, 0x02, None, None, 0x11, 0x03, "NTAG 215 504B")
    NTAG_216             = ChipInfo(54, 0x04, 0x02, None, None, 0x13, 0x03, "NTAG 216 888B")

    NTAG_I2C_PLUS_1K     = ChipInfo(55, 0x04, 0x05, None, None, 0x13, 0x03, "NTAG I2C plus 1k")
    NTAG_I2C_PLUS_2K     = ChipInfo(56, 0x04, 0x05, None, None, 0x15, 0x03, "NTAG I2C plus 2k")

    DUOX_2K              = ChipInfo(10, 0x01, None, 0xA0, None, 0x16, 0x05, "MIFARE DUOX 2K")
    DUOX_4K              = ChipInfo(10, 0x01, None, 0xA0, None, 0x18, 0x05, "MIFARE DUOX 4K")
    DUOX_8K              = ChipInfo(10, 0x01, None, 0xA0, None, 0x1A, 0x05, "MIFARE DUOX 8K")
    DUOX_16K             = ChipInfo(10, 0x01, None, 0xA0, None, 0x1C, 0x05, "MIFARE DUOX 16K")

    PLUS_SX_EV1_SL3_2K   = ChipInfo(12, 0x02, None, 0x11, None, 0x16, 0x05, "MIFARE Plus S/X EV1 SL3 2K")
    PLUS_SX_EV1_SL3_4K   = ChipInfo(13, 0x02, None, 0x11, None, 0x18, 0x05, "MIFARE Plus S/X EV1 SL3 4K")
    PLUS_SX_EV2_SL3_2K   = ChipInfo(15, 0x02, None, 0x22, None, 0x16, 0x05, "MIFARE Plus S/X EV2 SL3 2K")
    PLUS_SX_EV2_SL3_4K   = ChipInfo(16, 0x02, None, 0x22, None, 0x18, 0x05, "MIFARE Plus S/X EV2 SL3 4K")

    # IDENTIFIER                    NO  TYPE  SUBT  HWMAJ HWMIN SIZE  PROT  DESCRIPTION   
    DESFIRE_EV1_256B     = ChipInfo(21, 0x01, None, 0x01, None, 0x10, 0x05, "MIFARE DESFire EV1 256B")
    DESFIRE_EV1_2K       = ChipInfo(21, 0x01, None, 0x01, None, 0x16, 0x05, "MIFARE DESFire EV1 2k")
    DESFIRE_EV1_4K       = ChipInfo(22, 0x01, None, 0x01, None, 0x18, 0x05, "MIFARE DESFire EV1 4k")
    DESFIRE_EV1_8K       = ChipInfo(23, 0x01, None, 0x01, None, 0x1A, 0x05, "MIFARE DESFire EV1 8k")
    DESFIRE_EV2_2K       = ChipInfo(24, 0x01, None, 0x02, None, 0x16, 0x05, "MIFARE DESFire EV2 2k")
    DESFIRE_EV2_4K       = ChipInfo(25, 0x01, None, 0x02, None, 0x18, 0x05, "MIFARE DESFire EV2 4k")
    DESFIRE_EV2_8K       = ChipInfo(26, 0x01, None, 0x02, None, 0x1A, 0x05, "MIFARE DESFire EV2 8k")
    DESFIRE_EV2_16K      = ChipInfo(26, 0x01, None, 0x02, None, 0x1C, 0x05, "MIFARE DESFire EV2 16k")
    DESFIRE_EV2_32K      = ChipInfo(26, 0x01, None, 0x02, None, 0x1E, 0x05, "MIFARE DESFire EV2 32k")
    DESFIRE_EV3_2K       = ChipInfo(30, 0x01, None, 0x03, None, 0x16, 0x05, "MIFARE DESFire EV3 2k")
    DESFIRE_EV3_4K       = ChipInfo(31, 0x01, None, 0x03, None, 0x18, 0x05, "MIFARE DESFire EV3 4k")
    DESFIRE_EV3_8K       = ChipInfo(32, 0x01, None, 0x03, None, 0x1A, 0x05, "MIFARE DESFire EV3 8k")

    DESFIRE_LIGHT_512B   = ChipInfo(11, 0x08, None, None, None, 0x13, 0x05, "MIFARE DESFire Light 512B")

    # NTAG_X_DNA_4K        = ChipInfo(63, 0x07, 0x08, 0xA0, None, 0x1E, 0x05, "NTAG X DNA 4k")
    # NTAG_X_DNA_16K       = ChipInfo(64, 0x07, 0x08, 0xA0, None, 0x22, 0x05, "NTAG X DNA 16k")

    NTAG_424_DNA         = ChipInfo(60, 0x04, None, 0x30, 0x00, 0x11, 0x05, "NTAG 424 DNA")
    # NTAG_426Q_DNA        = ChipInfo(62, 0x04, None, 0x30, None, 0x15, 0x05, "NTAG 426Q DNA")

    NTAG_5_SWITCH        = ChipInfo(70, 0x07, None, None, None, 0x11, 0x05, "NTAG 5 Switch (ISO 15693)")
    NTAG_5_LINK          = ChipInfo(71, 0x07, None, None, None, 0x13, 0x05, "NTAG 5 Link 2K (ISO 15693)")

    @classmethod
    def identify(cls, card_version: CardVersion) -> Optional['MifareNtagType']:
        """
        Identifiziert den Chip basierend auf der 8-Byte Antwort von GET_VERSION (0x60).
        
        Wenn ein beliebiges Feld wie hw_sub_type None ist, wird es ignoriert.
        """
        log.debug(f"identify: Received card version: hw_type: {card_version.hw_type}, hw_sub_type: {card_version.hw_sub_type}, "
            f"hw_major_version: {card_version.hw_major_version}, hw_minor_version: {card_version.hw_minor_version}, "
            f"hw_storage_size: {card_version.hw_storage_size}, comm_protocol: {card_version.hw_protocol}")

        hw_type = card_version.hw_type
        hw_sub_type = card_version.hw_sub_type
        hw_major = card_version.hw_major_version
        hw_minor = card_version.hw_minor_version
        storage_size = card_version.hw_storage_size
        comm_protocol = card_version.hw_protocol

        card_id = MifareNtagType.UNKNOWN
        for chip in cls:
            if chip.value.hw_type == hw_type:
                if (chip.value.hw_sub_type is None or chip.value.hw_sub_type == hw_sub_type) and \
                   (chip.value.hw_major_version is None or chip.value.hw_major_version == hw_major) and \
                   (chip.value.hw_minor_version is None or chip.value.hw_minor_version == hw_minor) and \
                   (chip.value.comm_protocol is None or chip.value.comm_protocol == comm_protocol) and \
                   (chip.value.storage_size is None or chip.value.storage_size == storage_size):
                        card_id = chip
                        break
        return card_id
    
    @classmethod
    def getByID(cls, target_id: int):
        """
        Returns ChipInfo by its internal ID
        """
        for chip in cls:
            if chip.value.id == target_id:
                return chip
        return None

    def supportsGetVersion(className: str) -> bool:
        """
        Prüft, ob der gegebene Tag-Typ unterstützt wird.
        """

        if className in [
            "Topaz", "Topaz512",
            "NTAG210", "NTAG212", "NTAG213", "NTAG215", "NTAG216",
            "MifareUltralightEV1", "MF0UL11", "MF0ULH11", "MF0UL21", "MF0ULH21",
            "NT3H1101", "NT3H1201",
            "FelicaStandard", "FelicaMobile", "FelicaLite", "FelicaLiteS", "FelicaPlug",
            "Type4ATag", "Type4BTag"
        ]:
            return True
        else:
            return False

