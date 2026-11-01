import base64
import logging
import time
import os
from enum import Enum
from operator import attrgetter

from entity import (
    Issuer,
    Operation,
    ReaderKeyResponse,
    ReaderKeyRequest,
    HardwareFinishResponse,
    HardwareFinishColor,
    DeviceCredentialRequest,
    DeviceCredentialResponse,
    Endpoint,
    Enrollments,
    Enrollment,
    OperationStatus,
    SupportedConfigurationResponse,
    ControlPointRequest,
    ControlPointResponse,
)

from homekey import read_homekey, ProtocolError

from repository import Repository
from util.bfclf import (
    BroadcastFrameContactlessFrontend,
    RemoteTarget,
    activate,
    ISODEPTag,
)
from util.digital_key import DigitalKeyFlow, DigitalKeyTransactionType
from util.ecp import ECP
from util.iso7816 import ISO7816Tag
from util.threads import create_runner
from util.structable import pack_into_base64_string, unpack_from_base64_string
from util.tagtype import TagType

from desfire.key import DESFireKey
from desfire.schemas.key_settings import KeySettings
from desfire.enums import DESFireKeyType
from util.desfiretag import DESFireTag
from util.get_version_detection import MifareNtagType
from nfc.tag.manufacturer_name import getManufacturerShortName, isInManufacturerList, getDefaultManufacturerID


log = logging.getLogger(__name__)

# Define card/tag types
class TAGTYPE(Enum):
    TAG_UNKNOWN = 0
  
    MIFARE_CLASSIC_1K = 11
    MIFARE_CLASSIC_4K = 12

    MIFARE_ULTRALIGHT = 21
    MIFARE_ULTRALIGHT_EV1_11 = 22
    MIFARE_ULTRALIGHT_EV1_21 = 23
    MIFARE_ULTRALIGHT_C = 24
    NTAG_203 = 31
    NTAG_210 = 32
    NTAG_212 = 33
    NTAG_213 = 34
    NTAG_215 = 35
    NTAG_216 = 36

    MIFARE_PLUS_SL0 = 41
    MIFARE_PLUS_SL1 = 42

    UNKNOWN_ISO_14443_4 = 50
    MIFARE_DESFIRE_OR_PLUS_WITH_REAL_UID = 51
    MIFARE_DESFIRE_OR_PLUS_WITH_RANDOM_UID = 52
    MIFARE_DESFIRE_WITH_REAL_UID = 53
    MIFARE_DESFIRE_WITH_RANDOM_UID = 54
    MIFARE_PLUS_WITH_REAL_UID = 55
    MIFARE_PLUS_WITH_RANDOM_UID = 56
    
    APPLE_MOBILE = 80

class Service:
    def __init__(
        self,
        clf: BroadcastFrameContactlessFrontend,
        repository: Repository,
        express: bool = True,
        finish: str = "silver",
        flow: str = "fast",
        throttle_polling = 0.1
    ) -> None:
        self.repository = repository
        self.clf = clf
        self.throttle_polling = throttle_polling
        self.express = express in (True, "True", "true", "1")

        try:
            self.hardware_finish_color = HardwareFinishColor[finish.upper()]
        except KeyError:
            self.hardware_finish_color = HardwareFinishColor.BLACK
            log.warning(
                f"HardwareFinish {finish} is not supported. Falling back to {self.hardware_finish_color}"
            )
        try:
            self.flow = DigitalKeyFlow[flow.upper()]
        except KeyError:
            self.flow = DigitalKeyFlow.FAST
            log.warning(
                f"Digital Key flow {flow} is not supported. Falling back to {self.flow}"
            )

        self._run_flag = True
        self._runner = None

    def on_endpoint_authenticated(self, endpoint):
        """This method will be called when an endpoint is authenticated"""
        # Currently overwritten by accessory.py

    def start(self):
        self._runner = create_runner(
            name="homekey",
            target=self.run,
            flag=attrgetter("_run_flag"),
            delay=0,
            exception_delay=5,
            start=True,
        )

    def stop(self):
        self._run_flag = False
        if self._runner is not None:
            self._runner.join()

    def update_hap_pairings(self, issuer_public_keys):
        issuers = {
            issuer.public_key: issuer for issuer in self.repository.get_all_issuers()
        }
        for issuer in issuers.values():
            if issuer.public_key in issuer_public_keys:
                continue
            log.info(f"Removing issuer {issuer} as their pairing has been removed")
            self.repository.remove_issuer(issuer)

        for issuer_public_key in issuer_public_keys:
            if issuer_public_key in issuers:
                continue
            issuer = Issuer(public_key=issuer_public_key, endpoints=[])
            log.info(f"Adding issuer {issuer} based on paired clients")
            self.repository.upsert_issuer(issuer)

    def _read_homekey(self):
        start = time.monotonic()

        remote_target = self.clf.sense(
            RemoteTarget("106A"),
            broadcast=ECP.home(
                identifier=self.repository.get_reader_group_identifier(),
                flag_2=self.express,
            ).pack(),
        )

        if remote_target is None:
            # Throttle polling attempts to prevent overheating & RF performance degradation
            time.sleep(max(0, self.throttle_polling - time.monotonic() + start))
            return

        target = activate(self.clf, remote_target)
        if target is None:
            return

        # new card is detected
        log.info("-" * 80)

        # get basic card type infos: UID, ATQA (SENS_RES), SAK (SEL_RES)
        uid = target.identifier
        # atqa = int.from_bytes(target._target.sens_res, byteorder='little')
        atqa = int.from_bytes(target.atqa, byteorder='little')
        sak = int.from_bytes(target.sak, byteorder='little')

        log.info(f"NFCpy tag info: {target.tagInfo()}.")
        
        # Detect non-ISODEP tags (e.g., MIFARE Classic, Ultralight, Plus, NTAG 2xx, etc.)
        tag_type = TAGTYPE.TAG_UNKNOWN
        if not isinstance(target, ISODEPTag):
            log.info(f"Fingerprint of the ISO/IEC 14443-3 tag/card (non ISO-DEP) ...")

            if (atqa == 0x0004 and len(uid) == 4 and sak == 0x08):
                log.info("This is likely a MIFARE Classic 1K card (4-byte real UID, ATQA 0x0004, SAK 0x08).")
                tag_type = TAGTYPE.MIFARE_CLASSIC_1K
            elif (atqa == 0x0002 and len(uid) == 4 and sak == 0x18):
                log.info("This is likely a MIFARE Classic 4K card (4-byte real UID, ATQA 0x0002, SAK 0x18).")
                tag_type = TAGTYPE.MIFARE_CLASSIC_4K
            elif (atqa == 0x0044 and len(uid) == 7 and sak == 0x00):
                log.info("This is likely a MIFARE Ultralight (standard, EV1, C or AES) card (7-byte real UID, ATQA 0x0044, SAK 0x00).")
                tag_type = TAGTYPE.MIFARE_ULTRALIGHT
            elif ((atqa == 0x0042 or atqa == 0x0044) and (len(uid) == 4 or len(uid) == 7) and sak == 0x18):
                log.info("This is likely a MIFARE plus card with SL0 (delivery condition) card (4 or 7-byte UID, ATQA 0x0042 or 0x0044, SAK 0x18).")
                tag_type = TAGTYPE.MIFARE_PLUS_SL0
            elif ((atqa == 0x0042 or atqa == 0x0044) and (len(uid) == 4 or len(uid) == 7) and sak == 0x11):
                log.info("This is likely a MIFARE plus card with SL1 (compatibility mode) card (4 or 7-byte UID, ATQA 0x0042 or 0x0044, SAK 0x11).")
                tag_type = TAGTYPE.MIFARE_PLUS_SL1
            else:
                log.info("This is a ISO/IEC 14443-3 tag/card with unknown type.")
            miu = None
        else:
            # Get Maximum Information Unit - additional info for ISO-DEP cards 
            miu = target._dep.miu
            log.info(f"Fingerprint of the ISO/IEC 14443-4 tag/card (with ISO-DEP, Layer 4) ...")

            # DESFire (ISO 14443-4 cards) detection heuristic:
            if (atqa == 0x0344 and len(uid) == 7 and sak == 0x20):
                log.info(f"This is likely a DESFire (EV1, EV2, EV3) card or MIFARE Plus in SL3 mode (7-byte real UID, ATQA 0x0344, SAK 0x20), MIU {miu}.")
                tag_type = TAGTYPE.MIFARE_DESFIRE_OR_PLUS_WITH_REAL_UID
            elif (atqa == 0x0304 and len(uid) == 4 and sak == 0x20):
                log.info(f"This is likely a DESFire (EV1, EV2, EV3) card or MIFARE Plus in SL3 mode (4-byte random UID, ATQA 0x0304, SAK 0x20), MIU {miu}.")
                tag_type = TAGTYPE.MIFARE_DESFIRE_OR_PLUS_WITH_RANDOM_UID
            elif (atqa == 0x0004 and len(uid) == 4 and sak == 0x20) and uid.startswith(b'\x08'):
                log.info(f"This is likely an Apple iPhone (4-byte random UID starting with 0x08, ATQA 0x0004, SAK 0x20), MIU {miu}.")
                tag_type = TAGTYPE.APPLE_MOBILE
            else:
                log.info(f"This is a ISO/IEC 14443-4 tag/card with unknown type, {len(uid)}-byte UID, (ATQA 0x{atqa:04X}, SAK 0x{sak:02X}, MIU {miu}).")
                tag_type = TAGTYPE.UNKNOWN_ISO_14443_4

            # try get version
            log.info("try Get Version ...")
            frame = target.send_apdu(cla=0x90, ins=0x60, p1=0x00, p2=0x00, mrl=0, check_status=False)
            log.info(f"Get Version response (incl. status): {frame.hex().upper()}")
        
        # identify card type based on RF parameters
        legacy_id = TagType.fingerprint(uid, atqa, sak, miu)
        log.info(f"Fingerprint of card/tag based on RF params via enum: {legacy_id.value.description}, RF-ID: {legacy_id.value.id}.")

        # Special handling for Tesla key cards
        if legacy_id == TagType.TESLA_KEY_CARD:
            tag = DESFireTag(target)
            # try to get information from Tesla key card by selecting a known file first
            pubkey = tag.teslaGetPublicKey()
            card_info = tag.get_card_version()
            card_id = MifareNtagType.UNKNOWN
            if pubkey is not None:
                log.info(f"Tesla key card ECDH public key data (raw): {pubkey.hex().upper()}, length: {len(pubkey)} bytes, MIU {miu}.")

        # get version info if possible - only for certain tag types (DESFire, Ultralight), but not for Apple iPhone
        elif legacy_id != TagType.APPLE_MOBILE:

            # MifareNtagType.supportsGetVersion(className):
            log.info("Card/tag may support GetVersion (0x60) for detailed hardware info...")

            tag = DESFireTag(target)
            # dirty hack to differ between DESFire and Ultralight cards/tags
            tag.supportsISO7816 = ((sak & 0x20) == 0x20)  # only for ISO-DEP cards with SAK indicating ISO-DEP support (Bit 6 set, see NXP AN10833)
            card_info = tag.get_card_version()

            # verify that GetVersion was really supported by the card/tag
            if card_info.hw_vendor_id != 0x00:
                log.debug(f"Card/tag infos from GetVersion: {card_info}")

                # identify card type based on GetVersion info
                card_id = MifareNtagType.identify(card_info)
                log.info(f"Card/tag type identification based on GetVersion: {card_id.value.description}, EX-ID: {card_id.value.id}.")
            else:
                log.info("GetVersion command not supported by this card/tag!")
                card_id = MifareNtagType.UNKNOWN
        else:
            log.debug("Classic, simple, and unknown cards/tags as well as Apple iPhones do not support GetVersion.")
            card_id = MifareNtagType.UNKNOWN

        log.info(f"Overall card/tag identification result: {legacy_id.value.id}-{card_id.value.id}")

        # For your own ISO-DEP cards: authenticate to get real UID if possible 
        if isinstance(target, ISODEPTag) and card_id in (
            MifareNtagType.DESFIRE_EV1_2K,
            MifareNtagType.DESFIRE_EV1_4K,
            MifareNtagType.DESFIRE_EV1_8K,
            MifareNtagType.DESFIRE_EV2_2K,
            MifareNtagType.DESFIRE_EV3_4K,
            MifareNtagType.PLUS_SX_EV1_SL3_2K,
            MifareNtagType.PLUS_SX_EV1_SL3_4K,
            MifareNtagType.PLUS_SX_EV2_SL3_2K,
            MifareNtagType.PLUS_SX_EV2_SL3_4K
        ):

            # For your own DESFire cards only: start cryptic operations to prevent spoofing
            log.debug("Start with cryptic operations for YOUR OWN DESFire cards with personal keys.")

            # Use DESFire commands to get the real UID
            key_settings = KeySettings(0, DESFireKeyType.DF_KEY_AES)

            key = DESFireKey(key_settings, "CE7B3ECD113AE21A3F67A18190FDD901")  # PICC Master key for my home
            # key = DESFireKey(key_settings, "00000000000000000000000000000000")
            # key = DESFireKey(key_settings, "f2522e2bc5f41493088dcced34832b60")
            # key = DESFireKey(key_settings, "89634923c338213e94a056a45b2c194f")

            real_uid = tag.GetCardUID(key)
            if real_uid is None:
                log.error("Could not get real UID from DESFire tag. Maybe wrong key?")
            else:
                log.info(f"Real UID of DESFire card/tag: 0x{real_uid.hex().upper()} length: {len(real_uid)} bytes.")

        if tag_type != TAGTYPE.APPLE_MOBILE:
            log.info("=========================== Finished with card reading!")
            while self.clf.sense(RemoteTarget("106A")) is not None:
                log.info("Waiting for target to leave the field...")
                time.sleep(0.5)
            return
        
        log.info("Identified an Apple iPhone. Proceeding with Apple HomeKey reading...")
        # Proceed with HomeKey reading for Apple iPhone (ISODEPTag)
        tag = ISO7816Tag(target)
        try:
            result_flow, new_issuers_state, endpoint = read_homekey(
                tag,
                issuers=self.repository.get_all_issuers(),
                preferred_versions=[b"\x02\x00"],
                flow=self.flow,
                transaction_code=DigitalKeyTransactionType.UNLOCK,
                reader_identifier=self.repository.get_reader_group_identifier()
                + self.repository.get_reader_identifier(),
                reader_private_key=self.repository.get_reader_private_key(),
                key_size=16,
            )

            if new_issuers_state is not None and len(new_issuers_state):
                self.repository.upsert_issuers(new_issuers_state)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"Authenticated endpoint via {result_flow!r}: {endpoint}")
            else:
                log.info(f"Authenticated endpoint via {result_flow.name}")

            end = time.monotonic()
            log.debug(f"Transaction took {(end - start) * 1000} ms")

            if endpoint is not None:
                self.on_endpoint_authenticated(endpoint)
        except ProtocolError as e:
            log.info(f'Could not authenticate device due to protocol error "{e}"')

        # Let device cool down, wait for ISODEP to drop to consider comms finished
        while target.is_present:
            log.info("Waiting for device to leave the field...")
            time.sleep(0.5)
        log.info("Device left the field. Continuing in 2 seconds...")
        time.sleep(2)
        log.info("Waiting for next device...")

    def run(self):
        if self.repository.get_reader_private_key() in (None, b""):
            raise Exception("Device is not configured via HAP. NFC inactive")

        log.info("Connecting to the NFC reader...")

        self.clf.device = None
        self.clf.open(self.clf.path)
        if self.clf.device is None:
            raise Exception(
                f"Could not connect to NFC device {self.clf} at {self.clf.path}"
            )

        while self._run_flag:
            self._read_homekey()

    def get_reader_key(self, request: ReaderKeyRequest) -> ReaderKeyResponse:
        response = ReaderKeyResponse(
            key_identifier=self.repository.get_reader_group_identifier(),
        )
        return response

    def add_reader_key(self, request: ReaderKeyRequest) -> ReaderKeyResponse:
        changed = False
        if self.repository.get_reader_private_key() != request.reader_private_key:
            changed = True
            self.repository.set_reader_private_key(request.reader_private_key)
        if self.repository.get_reader_identifier() != request.unique_reader_identifier:
            changed = True
            self.repository.set_reader_identifier(request.unique_reader_identifier)
        response = ReaderKeyResponse(
            status=OperationStatus.SUCCESS if changed else OperationStatus.DUPLICATE
        )
        return response

    def remove_reader_key(self, request: ReaderKeyRequest) -> ReaderKeyResponse:
        if request.key_identifier == self.repository.get_reader_group_identifier():
            self.repository.set_reader_private_key(bytes.fromhex("00" * 32))
        response = ReaderKeyResponse(
            status=OperationStatus.SUCCESS
            if request.key_identifier == self.repository.get_reader_group_identifier()
            else OperationStatus.DOES_NOT_EXIST
        )
        return response

    def get_device_credential(
        self, request: DeviceCredentialRequest
    ) -> DeviceCredentialResponse:
        log.info(f"*** get_device_credential request={request}")

    def add_device_credential(
        self, request: DeviceCredentialRequest
    ) -> DeviceCredentialResponse:
        endpoint = self.repository.get_endpoint_by_public_key(
            b"\x04" + request.credential_public_key
        )
        log.info(f"*** add_device_credential endpoint={endpoint}")

        if endpoint is not None:
            if endpoint.enrollments.hap is None:
                issuer = self.repository.get_issuer_by_id(request.issuer_key_identifier)
                endpoint.enrollments.hap = Enrollment(
                    at=int(time.time()),
                    payload=base64.b64encode(request.pack()).decode(),
                )
                self.repository.upsert_endpoint(issuer.id, endpoint)
            return DeviceCredentialResponse(
                key_identifier=self.repository.get_reader_group_identifier(),
                status=OperationStatus.DUPLICATE,
            )

        issuer = self.repository.get_issuer_by_id(request.issuer_key_identifier)
        log.info(f"*** add_device_credential issuer={issuer}")

        if issuer is None:
            return DeviceCredentialResponse(
                key_identifier=self.repository.get_reader_group_identifier(),
                status=OperationStatus.DOES_NOT_EXIST,
            )

        self.repository.upsert_endpoint(
            issuer.id,
            Endpoint(
                last_used_at=0,
                counter=0,
                key_type=request.key_type,
                public_key=b"\x04" + request.credential_public_key,
                persistent_key=os.urandom(32),
                enrollments=Enrollments(
                    hap=Enrollment(
                        at=int(time.time()),
                        payload=base64.b64encode(request.pack()).decode(),
                    ),
                    attestation=None,
                ),
            ),
        )
        return DeviceCredentialResponse(
            issuer_key_identifier=issuer.id, status=OperationStatus.DUPLICATE
        )

    def remove_device_credential(
        self, request: DeviceCredentialRequest
    ) -> DeviceCredentialResponse:
        log.info(f"*** remove_device_credential request={request}")

    def get_hardware_finish(self):
        result = pack_into_base64_string(
            HardwareFinishResponse(color=self.hardware_finish_color)
        )
        log.debug(f"get_hardware_finish: color={self.hardware_finish_color}, result={result}")
        return result

    def get_nfc_access_supported_configuration(self):
        result = pack_into_base64_string(
            SupportedConfigurationResponse(
                number_of_issuer_keys=16, number_of_inactive_credentials=16
            )
        )
        log.debug(f"TODO get_nfc_access_supported_configuration={result} ")
        return result

    def get_nfc_access_control_point(self):
        log.debug("get_nfc_access_control_point")
        return ""

    def set_nfc_access_control_point(self, value):
        log.info(f"<-- (B64) {value}")
        request_packed_tlv = unpack_from_base64_string(value)
        log.info(f"<-- (TLV) {request_packed_tlv.hex()}")
        request: ControlPointRequest = ControlPointRequest.unpack(request_packed_tlv)
        log.info(f"<-- (OBJ) {request}")
        operation = request.operation
        response = ControlPointResponse()

        if request.device_credential_request is not None:
            subrequest: DeviceCredentialRequest = request.device_credential_request
            response.device_credential_response = (
                self.get_device_credential(subrequest)
                if operation == Operation.GET
                else self.add_device_credential(subrequest)
                if operation == Operation.ADD
                else self.remove_device_credential(subrequest)
                if operation == Operation.REMOVE
                else None
            )
        elif request.reader_key_request is not None:
            subrequest: ReaderKeyRequest = request.reader_key_request
            response.reader_key_response = (
                self.get_reader_key(subrequest)
                if operation == Operation.GET
                else self.add_reader_key(subrequest)
                if operation == Operation.ADD
                else self.remove_reader_key(subrequest)
                if operation == Operation.REMOVE
                else None
            )
        log.info(f"--> (OBJ) {response}")
        packed_tlv_response = response.pack()
        log.info(f"--> (TLV) {packed_tlv_response.hex()}")
        response = pack_into_base64_string(packed_tlv_response)
        log.info(f"--> (B64) {response}")
        return response

    def get_configuration_state(self):
        log.debug("get_configuration_state")
        return 0
