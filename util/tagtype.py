import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

@dataclass
class TagTypeRFinfo:
    id: int
    uid_len: int            # 4, 7, or 10 byte (10-byte UID is rare, so it's not used here yet)
    uid0: Optional[int]     # None means: 1st byte of UID is not relevant for identification, otherwise it should match this value to avoid misidentification (e.g. Apple iPhone with same SAK/ATQA as DESFire cards)
    atqa: Optional[int]     # None means: atqa is not relevant for identification
    sak: Optional[int]      # None means: sak is not relevant for identification
    miu: Optional[int]      # None means: miu is not relevant for identification
    isModern: bool          # indicates if command 0x60 GetVersion is supported, this is the case for modern cards like 
                            # DESFire, Ultralight, NTAG, but not for Classic or Plus in SL0/1 mode
    description: str

class TagType(Enum):
    """
    Returns matching card type to RF-params
    
    Identifies potential card types based on RF parameters (UID, ATQA, SAK) as a first step. Main indicator is SAK. ATQA is used as secondary indicator
    to distinguish between similar cards (e.g. MIFARE Classic vs. MIFARE Plus in SL0/1 mode). UID length is also considered.

    Notes:
    4-byte UID is typical for older cards, 7-byte UID for newer cards.
    4-byte UID is also typical for random UIDs used in DESFire cards or Plus cards in SL3 mode.
    10-byte UID is rare, but possible for certain cards - not used here (used in large scale logistic systems).
    """

    """
    Copilot said: 
    What Does Each Bit in the SAK Represent?
    The SAK value (Select Acknowledge) in RFID/NFC systems (according to ISO/IEC 14443-3) is used to indicate the properties and capabilities of a card or tag.
    It is provided by the tag during the anti-collision and selection process starting at the ISO/IEC 14443-3 layer. The SAK helps the reader identify 
    the card type and its supported features.

    The SAK value is a 1-byte value (8 bits), and each bit has a specific meaning depending on the implementation and card type.

    SAK Structure
    The SAK value is an 8-bit field (1 byte), with the bits interpreted as follows:

    Bit in SAK Byte	Description	Meaning/Use
    Bit 7 (MSB)	ISO compliance: 1 = ISO/IEC 14443-4 compliant, 0 = not compliant.	Indicates whether the card supports block communication under ISO/IEC 14443-4.
    Bit 6 Anti-collision cascade level: 1 = UID fully transmitted (end of cascade).	Shows if the card has completed the cascade process for its UID.
    Bit 5 NFC compliance: 0 = legacy compatibility only, 1 = NFC compliant.	Indicates whether the card supports NFC commands.
    Bit 4 MIFARE Classic compatibility: 1 = MIFARE Classic commands supported.	Indicates if the card supports or emulates MIFARE Classic functionality.
    Bit 3–1 (Reserved)	Reserved for manufacturer-specific or future applications.	May be used to indicate additional features or modes (not standard).
    Bit 0 (LSB)	Parity Bit: Ensures the total number of set bits in the SAK byte is even.	Used to ensure SAK data integrity using an even-parity check.

    Detailed Description of Key Bits in SAK
    Bit 8: Reserved for future use (RFU).
    Bit 7: Indicating ISO/IEC 14443-4 compliance (part 4 support).
    Bit 6: PICC (Proximity Card) is part of the ISO/IEC 14443-4 standard.
    Bit 5: Special application functionality or protocol (e.g., indicates support for proprietary protocols).
    Bits 4, 3, 2: Diese Bits kennzeichnen spezifische Typen von Karten.
    Bit 1 (LSB): Indikator für weitere hierarchische Informationen.

    Bit 7 – ISO/IEC 14443-4 Compliance
    1: The card supports block-based communication as described by ISO/IEC 14443-4 (e.g., used for secure applications like payment cards).
    0: The card operates under ISO/IEC 14443-3 and does not support ISO/IEC 14443-4 (e.g., MIFARE Classic or simpler tags).
    Bit 6 – UID Cascade Level
    1: The UID of the card has been fully transmitted, signaling the end of the UID cascade process.
    0: The full UID hasn’t been sent yet; the card is still in the anti-collision phase (common for 7-byte UIDs requiring cascaded levels).
    Bit 5 – NFC Compliance
    1: The card is compliant with NFC standards and supports NFC-specific commands.
    0: The card does not support NFC and may follow legacy standards only.
    Bit 4 – MIFARE Classic Compatibility
    1: The card is compatible with MIFARE Classic command sets.
    0: The card does not support MIFARE Classic legacy commands, such as authentication and sector operations.
    Bits 3–1 – Reserved or Implementation-Specific
    These bits are generally reserved for manufacturer-specific implementations or used for future functionality.
    Bit 0 – Parity Bit
    The parity bit ensures the overall integrity of the SAK byte. The number of 1-bits in the SAK byte, including bit 0, must be even.
    """

    """
    The ATQA (Answer To Request for Type A) is a 2-byte (16-bit) value sent by an NFC or RFID card/tag to the reader during the initial
    communication (anti-collision or wake-up process). The ATQA value provides information about the card’s properties, including its 
    supported technology features, UID length, and the presence of specific functionality.

    The meaning of the ATQA bits can vary depending on the card type, as ISO/IEC 14443-3 Type A defines the base standard but leaves 
    some bits as manufacturer- or application-specific.

    General Structure of ATQA
    Bits	Description
    Bit 15 (MSB)	1 = UID continues (cascade required), 0 = UID is fully sent.
    Bits 14–10	Reserved (often manufacturer-specific or implementation-specific).
    Bit 9	1 = UID length is 7 bytes. 0 = UID length is 4 bytes or 10 bytes.
    Bits 8–6	Technology/feature indicators (e.g., proprietary features or compliance flags).
    Bit 5	Anti-collision compliance (ISO/IEC 14443-3).
    Bit 4–0 (LSB)	Reserved or manufacturer-specific (used for particular sub-features of cards).
    Detailed Description of Key ATQA Bits
    Bit 15 – UID Cascade Indication (MSB)
    Indicates whether further UID cascade levels are required during anti-collision.
    1: The tag has a longer UID (e.g., 7-byte or 10-byte UID), and cascading to the next level is necessary to obtain the full UID.
    0: The tag has a short UID (4 bytes), and no further cascading is required.
    Bit 9 – UID Length
    Dictates the length of the tag's UID:
    1: The tag has a 7-byte UID, which is used to ensure global uniqueness in environments with multiple tags.
    0: The tag has a 4-byte UID or supports 10-byte UID (sometimes used in high-security contexts).
    Bits 8–6 – Additional Features and Compliance
    These bits are implementation- and manufacturer-specific and are used to signal support for proprietary features or compliance with specific protocols.
    Examples:
    These can indicate advanced tag capabilities such as additional security functionality or application-specific features.
    Bit 5 – Anti-Collision Compliance
    Indicates whether the card fully supports the anti-collision process required by ISO/IEC 14443-3.
    1: The card adheres to anti-collision protocols.
    0: No support for advanced anti-collision (e.g., simple tags without collision handling).
    Bits 4–0 – Reserved/Manufacturer-Specific
    These bits may transmit extra details defined by the card manufacturer.
    For example, these reserved bits are sometimes used to signal specific chip types, applications, or modes of operation.
"""

    UNKNOWN             = TagTypeRFinfo(00, 0, None, 0xFFFF, 0xFF, 0, False, "Unknown card type")
    # MIFARE Classic Series: DOES NOT support GetVersion, UID is 4 Byte, but can be 7 Byte as well)
    MINI                = TagTypeRFinfo(10, 4, None, 0x0004, 0x09, None, False, "MIFARE mini")
    CLASSIC_1K          = TagTypeRFinfo(11, 4, None, 0x0004, 0x08, None, False, "MIFARE Classic 1K or Plus S/X/SE in SL0/1 mode (Classic compatibility) with 4-byte UID")
    CLASSIC_2K          = TagTypeRFinfo(12, 4, None, 0x0004, 0x19, None, False, "MIFARE Classic 2K with 4-byte UID")
    CLASSIC_4K          = TagTypeRFinfo(13, 4, None, 0x0004, 0x18, None, False, "MIFARE Classic 4K or Plus S/X in SL0/1 mode (Classic compatibility) with 4-byte UID")
    CLASSIC_1K_7B       = TagTypeRFinfo(14, 7, None, 0x0002, 0x08, None, False, "MIFARE Classic 1K or Plus S/X/SE in SL1 mode (Classic compatibility) with 7-byte UID")
    CLASSIC_2K_7B       = TagTypeRFinfo(15, 7, None, 0x0002, 0x19, None, False, "MIFARE Classic 2K or Plus S/X in SL1 mode (Classic compatibility) with 7-byte UID")
    CLASSIC_4K_7B       = TagTypeRFinfo(16, 7, None, 0x0002, 0x18, None, False, "MIFARE Classic 4K or Plus S/X in SL1 mode (Classic compatibility) with 7-byte UID")
    
    # Ultralight / NTAG Family (Type 2 Tags): support GetVersion (except very old Ultralight cards)
    ULTRALIGHT_NTAG2_4B = TagTypeRFinfo(20, 4, None, 0x0044, 0x00, None, True, "MIFARE Ultralight Series, NTAG 2xx with 4-byte UID")
    ULTRALIGHT_NTAG2_7B = TagTypeRFinfo(21, 7, None, 0x0044, 0x00, None, True, "MIFARE Ultralight Series, NTAG 2xx, I2C, or I2C Plus with 7-byte UID")
    NTAG5               = TagTypeRFinfo(22, 7, None, 0x0344, 0x00, None, True, "NTAG 5") # to be tested
    SHELL_RECHARGE_CARD = TagTypeRFinfo(23, 7, 0x04, 0x0044, 0x08, None, False, "Shell Recharge card with 7-byte real UID")
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
    APPLE_MOBILE        = TagTypeRFinfo(50, 4, 0x08, 0x0004, 0x20, None, False, "Apple mobile phone with 4-byte random UID") # this entry should prevent cards with same SAK/ATQA from being misidentified as DESFire
    TESLA_KEY_CARD      = TagTypeRFinfo(51, 7, 0x04, 0x0048, 0x20, None, True, "Tesla key card with 7-byte real UID")
    BANKING_CARD        = TagTypeRFinfo(52, 7, 0x05, 0x0044, 0x20, None, False, "Banking card (e.g., Visa Debit/Credit) with 7-byte real UID")
    IDENTITY_CARD       = TagTypeRFinfo(53, 7, 0x08, 0x0008, 0x20, None, False, "Identity card with 4-byte random UID")

    # Generic entries for MIFARE DESFire Family, Plus in SL3 mode, NTAG 4xx, or X DNA that support further identification by GetVersion (0x60) command
    DESFIRE_PLUS_NTAG4  = TagTypeRFinfo(30, 7, 0x04, None, 0x20, None, True, "MIFARE DESFire Family, Plus in SL3 mode, NTAG 4xx, or X DNA with 7-byte UID")
    DESFIRE_PLUS_4B     = TagTypeRFinfo(31, 4, 0x80, None, 0x20, None, True, "MIFARE DESFire Family, Plus in SL3 mode, NTAG 4xx, or X DNA with 4-byte random UID")

    # MIFARE Plus: support GetVersion, but only with SL0 (for unambiguous identification) and SL3
    PLUS_S_SL3_2K_7B    = TagTypeRFinfo(40, 7, 0x04, 0x0344, 0x10, None, False, "MIFARE Plus S/X with 2K in SL2 mode (hybrid security)") # Security Level 2
    PLUS_S_SL3_2K_4B    = TagTypeRFinfo(41, 4, 0x80, 0x0344, 0x10, None, False, "MIFARE Plus S/X with 2K in SL2 mode (hybrid security)") # Security Level 2
    PLUS_S_SL3_4K_7B    = TagTypeRFinfo(42, 7, 0x04, 0x0344, 0x11, None, False, "MIFARE Plus S/X with 4K in SL2 mode (hybrid security)") # Security Level 2
    PLUS_S_SL3_4K_4B    = TagTypeRFinfo(43, 4, 0x80, 0x0344, 0x11, None, False, "MIFARE Plus S/X with 4K in SL2 mode (hybrid security)") # Security Level 2

    @classmethod
    def fingerprint(cls, uid: bytes, atqa: int, sak: int, miu: int) -> 'TagTypeRFinfo':
        """
        Returns matching card type to RF-params 
        
        Identifies potential card types based on RF parameters (UID, ATQA, SAK) as a first step
        """
    
        log.debug(f"fingerprint called: uid_len: {len(uid)}, atqa: {hex(atqa)}, sak: {hex(sak)}")
        card_type = TagType.UNKNOWN  # Return UNKNOWN if no match found
        for card in cls:
            if card.value.uid_len != len(uid):
                continue
            if card.value.uid0 is not None and card.value.uid0 != uid[0]:
                continue
            if card.value.atqa is not None and card.value.atqa != atqa:
                continue
            if card.value.sak is not None and card.value.sak != sak:
                continue
            if card.value.miu is not None and card.value.miu != miu:
                continue
            card_type = card
            break

        return card_type
