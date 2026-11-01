import logging

from Crypto.Random import get_random_bytes

import nfc.tag
from nfc.tag.tt4 import Type4Tag
from nfc.clf.device import Device 

from desfire.key import DESFireKey
from desfire.enums import DESFireCommand, DESFireCommunicationMode
from desfire.schemas import CardVersion
from desfire.util import CRC32, get_list, to_hex_string
from desfire.DESFire import DESFire
from desfire.enums.desfire_keysettings import DESFireKeySettings

#from desfire.DESFire import DESFire, get_card_version, memory_size, manufacturer, product_type, product_subtype, \
#    major_product_version, minor_product_version, protocol_type, fw_major_version, fw_minor_version, uid, batch_number, production_week, production_year

from util.iso7816 import ISO7816Command, ISO7816Response, ISO7816Class, ISO7816StatusGroup
from typing import Any, Union
from typing import Tuple
from homekey import ProtocolError

log = logging.getLogger(__name__)

# see https://www.nxp.com/docs/en/application-note/AN10833.pdf (Chapter 2.1) for hardware types
def manufacturer_name(manufacturer: int) -> str:
    match manufacturer:
        case 0x04:  # NXP
            return "NXP"
        case 0x05:  # STMicroelectronics
            return "STMicroelectronics"
        case _:     # Default for unknown manufacturers
            return "Unknown"

# hw/product type definitions from NXP application note AN10833, chapter 2.1, table 1
# see https://www.nxp.com/docs/en/application-note/AN10833.pdf
def product_type_name(product_type: int) -> str:
    match product_type:
        case 0x01:  # MIFARE DESFire family
            return "MIFARE DESFire"
        case 0x01:  # MIFARE Plus family
            return "MIFARE Plus"
        case 0x03:  # MIFARE Ultralight family
            return "MIFARE Ultralight"
        case 0x04:  # NTAG family
            return "NTAG"
        case 0x05:  # Reserved for future use (RFU) - as a placeholder in 2026
            return "Future use"
        case 0x06:  # Reserved for future use (RFU) - as a placeholder in 2026
            return "Future use"
        case 0x07:  # NTAG I2C family
            return "NTAG I2C"
        case 0x08:  # MIFARE DESFire Light family
            return "MIFARE DESFire Light"
        case 0xA1:  # MIFARE DUOX
            return "MIFARE DUOX"
        case _:     # Default for unknown product types
            return "Unknown"

# figure 1 in the an shows a detailed flow diagram that includes subtypes
def product_subtype_name_desfire(product_subtype: int) -> str:
    match product_subtype:
        case 0x01:
            return "EV1"
        case 0x02:
            return "EV2"
        case 0x03:
            return "EV3"
        case _:     # Default for unknown product subtypes
            return "Unknown"

def product_subtype_name_plus(product_subtype: int) -> str:
    match product_subtype:
        case 0x11:
            return "EV1"
        case 0x22:
            return "EV2"
        case _:     # Default for unknown product subtypes
            return "Unknown"

def product_subtype_name_ultralight(product_subtype: int) -> str:
    match product_subtype:
        case 0x10:
            return "C"
        case 0x15:
            return "nano"
        case 0x02:
            return "EV1"
        case 0x05:
            return "AES"
        case _:     # Default for unknown product subtypes
            return "Unknown"

def product_subtype_name_ntag(code: int) -> str:
    match code:
        case 209: # hex 0xD1
            return "210u"
        case 210: # hex 0xD2
            return "210"
        case 212: # hex 0xD4
            return "212"
        case 213: # hex 0xD5
            return "213"
        case 215: # hex 0xD7
            return "215"
        case 216: # hex 0xD8
            return "216"
        case 0x30:
            return "I2C"
        case 0x31:
            return "I2C plus"
        case 0x41:
            return "413 DNA"
        case 0x42:
            return "424 DNA"
        case 0x43:
            return "X DNA"
        case 0x51:
            return "5 link/boost"
        case 0x52:
            return "5 switch"
        case _:     # Default for unknown product subtypes
            return "Unknown"

def memory_size_bytes(size: int) -> int:
    match size:
        case 0x10: 
            return 256
        case 0x13: 
            return 512
        case 0x16: 
            return 2048
        case 0x18: 
            return 4096
        case 0x1A: 
            return 8192
        case 0x1C: 
            return 16384
        case 0x1E: 
            return 32768
        case _:     # Default for unknown memory sizes
            return 0

def format_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    return f"{num_bytes / 1024:.1f} KB"

def protocol_type_name(protocol_type: int) -> str:
    match protocol_type:
        case 0x03:
            return "ISO/IEC 14443-3"
        case 0x05:
            return "ISO/IEC 14443-4"
        case _:     # Default for unknown protocol types
            return "Unknown"

class DESFireTag(DESFire):
    def __init__(self, target: Any) -> None:
        self._target = target

        super().__init__(self)
        log.debug(f"New Desfire Object created {self}.")
        #log.debug(f"New Desfire Object has {dir(self._target)}.")

    def transceive(self, data: Union[bytes, ISO7816Command]) -> Union[bytes, ISO7816Response]:
        log.debug(f"DESFireTag Transceive will execute transceive from {self._target}.")
        if isinstance(data, ISO7816Command):
            # Commands that are wrapped into ISO7816Command objects will return ISO7816Response objects
            log.debug(f"DESFireTag Transceive ISO7816 data: 0x{bytes(data.pack()).hex().upper()}")
            try:
                response = self._target.transceive(bytes(data.pack()))
            except nfc.tag.TagCommandError as e:
                if e.errno == nfc.tag.TIMEOUT_ERROR:
                    log.warning("DESFireTag Transceive timeout! Card/tag did not respond in time. Empty response and error code will be returned.")
                    # Return an empty response with an error status
                    return ISO7816Response(sw1=ISO7816StatusGroup.ERROR_COMMAND_NOT_ALLOWED, sw2=0x00, data=bytearray())
                else:
                    # log.error(f"DESFireTag Transceive TagCommandError during transceive! ERROR: {e}")
                    raise ProtocolError(f"DESFireTag Transceive TagCommandError - ERROR: {e}")
            except Exception as e:
                log.error(f"Error during transceive: {e}")
                raise ProtocolError(f"DESFireTag Transceive CMD EXCEPTION - ERROR: {e}")

            response = ISO7816Response.unpack(response)
            log.debug(f"DESFireTag Received ISO7816 response: {response}")
            return response
        else:
            # Plain byte commands will return plain byte responses
            log.debug(f"DESFireTag Transceive plain data: 0x{data.hex().upper()}")
            try:
                response = self._target.transceive(data)
            except nfc.tag.TagCommandError as e:
                if e.errno == nfc.tag.TIMEOUT_ERROR:
                    log.warning("DESFireTag Transceive timeout! Card/tag did not respond in time. Empty response and error code will be returned.")
                    return bytearray(b'\xFF')  # Indicate empty response with 0xFF
                else:
                    # log.error(f"DESFireTag Transceive TagCommandError during transceive! ERROR: {e}")
                    raise ProtocolError(f"DESFireTag Transceive TagCommandError - ERROR: {e}")
            except Exception as e:
                log.error(f"Error during transceive: {e}")
                raise ProtocolError(f"DESFireTag Transceive CMD EXCEPTION - ERROR: {e}")

            log.debug(f"DESFireTag Received plain response: {response.hex().upper()}")
            return response


    def GetCardUID(self, key: DESFireKey) -> bytes:
    

        # 1. Authentifizierung ist zwingend notwendig für GetCardUID
        # Standardmäßig ist oft der Master Key (0x00) mit 8 oder 16 Null-Bytes belegt
        self.authenticate(0, key)
        if self.is_authenticated:
            log.debug(f"GET CARD UID: 0x{self.device} Authenticated successfully.")
        else:
            log.debug(f"Authentication failed for DESFire tag/card. {key}")
            return None

        # 2. Echte UID abfragen (Befehl 0x51: GetCardUID)
        response = self.get_real_uid()
        if response is None:
            log.debug(f"Could not get real UID from DESFire tag/card. {self}") 
            return None
        real_uid = bytes(response)
        # print(f"Echte 7-Byte UID: {to_hex_string(real_uid)}")
        log.debug(f"Real 7-Byte UID: 0x{real_uid.hex().upper()} length: {len(real_uid)} bytes.")
        

        return real_uid

    def GetVersion(self) -> CardVersion:

        # Get Version (0x60) command

        return get_card_version()


    def GetVersionDesfire(self) -> Tuple[int, int, int, int, int, int, int, int, int, bytes, bytes, int, int]:

        log.debug(f"Tag/card info: {manufacturer_name(manufacturer)} {product_type_name(product_type)} {product_subtype_name_desfire(product_subtype)}, "
                f"hw version: {major_product_version}.{minor_product_version}, memory size: {format_size(memory_size_bytes(memory_size))}, protocol type: {protocol_type_name(protocol_type)}, "
                f"fw version: {fw_major_version}.{fw_minor_version}, uid: 0x{uid.hex().upper()}, batch number: 0x{batch_number.hex().upper()}, "
                f"production (week/year): {production_week:02X}/{production_year:02X}")

        return manufacturer, product_type, product_subtype, major_product_version, minor_product_version, memory_size, protocol_type, \
            fw_major_version, fw_minor_version, \
            uid, batch_number, production_week, production_year

    def iso_select_file(self, file_name: list[int] | str | bytearray | int | bytes) -> list[list[int]]:
        """
        Lists all application currently configured on the card.

        Authentication:
            Not required.

        Returns:
            list[list[int]]: List of application IDs, in a 4 byte hex form
        """
        log.info(f"Executing command: iso_select_file (0x{DESFireCommand.ISO_SELECT_FILE.value:02x} '{file_name}')")
        raw_data = self._transceive(
            self._command(DESFireCommand.ISO_SELECT_FILE.value, file_name.encode('utf-8') if isinstance(file_name, str) else get_list(file_name)),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
            iso_7816_4_class = ISO7816Class.INTERINDUSTRY
        )
        log.debug(f"Response as raw data: {to_hex_string(raw_data)}")

        return raw_data

    def teslaGetPublicKey(self, ) -> bytes:
        """
        Get Tesla key card public key by selecting known file.

        Authentication:
            No.

        Returns:
            public key data as raw bytes
        """

        """
        # Select Tesla Application 'teslaLogic002'
        AID = bytes.fromhex("7465736C614C6F67696330303201")  # 'teslaLogic002' with trailing 0x01 in hex

        # get public key by proprietary command
        command = ISO7816Command(
            cla=ISO7816Class.INTERINDUSTRY, ins=0xA4, p1=0x04, p2=0x00, data=AID, le=0x00
        )
        try:
            response = self.transceive(command)
        except Exception as e:
            log.error(f"teslaGetPublicKey CMD ERROR: {e}")
            raise ProtocolError(f"teslaGetPublicKey CMD EXCEPTION - ERROR: {e}")

        log.info(f"teslaGetPublicKey RES = {response}")
        """

        # Get public ECDH key no 0
        command = ISO7816Command(
            cla=ISO7816Class.PROPRIETARY, ins=0x04, p1=0x00, p2=0x00, data=None, le=0x00
        )
        try:
            response = self.transceive(command)
        except Exception as e:
            log.error(f"teslaGetPublicKey CMD ERROR: {e}")
            raise ProtocolError(f"teslaGetPublicKey CMD EXCEPTION - ERROR: {e}")

        log.debug(f"teslaGetPublicKey RES = {response}")

        return response.data
