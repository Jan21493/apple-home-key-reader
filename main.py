import json
import logging
import colorlog
import signal
import sys
import argparse
import logging

from pyhap.accessory_driver import AccessoryDriver

from accessory import Lock
from repository import Repository
from service import Service
from util.bfclf import BroadcastFrameContactlessFrontend

log = logging.getLogger(__name__)

DEBUG1 = 9
logging.addLevelName(DEBUG1, "DEBUG-1")

# By default, files that contain configuration, signatures and own cards are located in the same folder as the project
CONFIGURATION_FILE_PATH = "configuration.json"
MYCARDS_FILE_PATH = "myCards.json"


def load_configuration(path=CONFIGURATION_FILE_PATH) -> dict:
    """Load configuration from a JSON file or fallback to defaults."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            configuration = {**json.load(f)}
            print(f"Configuration loaded from {path}")
            return configuration
    except FileNotFoundError:
        # File not found, fallback to defaults
        print(f"File {path} not found. Using default configuration.")
        json_config = """
        {
            "logging": {
                "level": 20
            },
            "nfc": {
                "path": "tty:ttyUSB0:pn532",
                "broadcast": true
            },
            "hap": {
                "port": 51926,
                "persist": "hap.state",
                "default": "locked",
                "pincode": "123-45-678",
                "lock-name": "My NFC Lock",
                "info_manufacturer": "My Manufacturer",
                "info_model": "My Lock Model",
                "info_firmware_revision": "1.0",
                "info_serial_number": "01.02.03.04"
            },
            "homekey": {
                "persist": "homekey.json",
                "express": true,
                "finish": "silver",
                "flow": "fast"
            },
            "cardsignatures": {
                "path": "cardsignatures.json"
            }
        }
        """
        return {**json.loads(json_config)}
    except Exception as e:
        print(f"Failed to load configuration from a JSON file: {e}")
        raise e


def configure_logging(config: dict, logLevel=None) -> logging.Logger:
    log = logging.getLogger()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)8s] %(module)-18s:%(lineno)-4d %(message)s"
    )
    formatter = colorlog.ColoredFormatter(
        "%(log_color)s[%(asctime)s] [%(levelname)8s] %(module)-18s:%(lineno)-4d %(reset)s %(message_log_color)s%(message)s%(reset)s",
        log_colors={
            'DEBUG':    'black',
            'INFO':     'blue', 
            'WARNING':  'purple', 
            'ERROR':    'bold_red',
            'CRITICAL': 'bold_red,bg_black',
        },
        secondary_log_colors={
            'message': {
                'DEBUG':    'black',
                'INFO':     'blue',
                'WARNING':  'purple',
                'ERROR':    'bold_red',
                'CRITICAL': 'bold_red,bg_black',
            },
        },
        reset=True,
        style='%'
    )
    hdlr = colorlog.StreamHandler(sys.stdout)

    if logLevel is None:
        logLevel = config.get("level", logging.INFO)
    log.setLevel(logLevel)
    hdlr.setFormatter(formatter)
    log.addHandler(hdlr)
    log.info(f"Log level set to {logging.getLevelName(logLevel)} ({logLevel}).")

    return log

def load_mycards(path=MYCARDS_FILE_PATH) -> dict:
    """Load trusted cards from a JSON file or fallback to defaults."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            myCards = json.load(f)
            log.info(f"Trusted cards loaded from {path}")
            return myCards
    except FileNotFoundError:
        # File not found, fallback to defaults
        log.error(f"File {path} not found. Using empty trusted card list.")
        myCards = dict()
        return myCards
    except Exception as e:
        log.error(f"Failed to load trusted cards from a JSON file: {e}")
        raise e

def configure_hap_accessory(config: dict, homekey_service=None):
    driver = AccessoryDriver(port=config["port"], persist_file=config["persist"], pincode=bytes(config["pincode"], "utf-8"))
    accessory = Lock(
        driver,
        # "NFC Lock",
        f"{(config.get('lock-name') or 'My NFC Lock')}",
        service=homekey_service,
        lock_state_at_startup=int(config.get("default") != "unlocked")
    )
    accessory.set_info_service(
        manufacturer=f"{(config.get('info_manufacturer') or 'My Manufacturer')}",
        model=f"{(config.get('info_model') or 'Model')}",
        firmware_revision=f"{(config.get('info_firmware_revision') or '0')}",
        serial_number=f"{(config.get('info_serial_number') or '0.0')}"
    )
    driver.add_accessory(accessory=accessory)
    return driver, accessory


def configure_nfc_device(config: dict):
    clf = BroadcastFrameContactlessFrontend(
        path=config.get("path", None) or f"tty:{config.get('port')}:{config.get('driver')}",
        broadcast_enabled=config.get("broadcast", True),
    )
    return clf


def configure_homekey_service(config: dict, nfc_device, repository=None):
    service = Service(
        nfc_device,
        repository=repository or Repository(config["persist"]),
        express=config.get("express", True),
        finish=config.get("finish"),
        flow=config.get("flow"),
        # Poll no more than ~6 times a second by default
        throttle_polling=float(config.get("throttle_polling") or 0.15),
    )
    return service


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--log-level", "-l",
        default="",
        help="Logging level: CRITICAL, ERROR, WARNING, INFO, DEBUG, DEBUG-1 or a number (e.g. 9)"
    )
    return p.parse_args()


def resolve_level(s: str) -> int:
    s = s.upper()
    if s in ("DEBUG-1", "DEBUG1"):
        return DEBUG1
    if s.isdigit():
        return int(s)
    return getattr(logging, s)


def main():
    args = parse_args()

    config = load_configuration()

    # Log Level as parameter has priority over configuration file, if set
    log = configure_logging(config["logging"], resolve_level(args.log_level))
    logLevel = log.getEffectiveLevel()

    log.info("started")
    log.debug("debug enabled")

    logging.getLogger('nfc.clf.transport').setLevel(logLevel)
    logging.getLogger('nfc.clf.pn53x').setLevel(logLevel)
    logging.getLogger('nfc.clf.pn532').setLevel(logLevel)
    logging.getLogger('nfc.clf.device').setLevel(logLevel)
    logging.getLogger('nfc.clf.__init__').setLevel(logLevel)
    logging.getLogger('nfc.clf').setLevel(logLevel)
    logging.getLogger('nfc.tag').setLevel(logLevel)
    logging.getLogger('nfc.tag.tt2').setLevel(logLevel)
    logging.getLogger('nfc.tag.tt4').setLevel(logLevel)
    logging.getLogger('nfc.tag.tt2_nxp').setLevel(logLevel)
    logging.getLogger('nfc.dep').setLevel(logLevel)

    mycards = load_mycards()
    nfc_device = configure_nfc_device(config["nfc"])
    homekey_service = configure_homekey_service(config["homekey"], nfc_device)
    hap_driver, _ = configure_hap_accessory(config["hap"], homekey_service)

    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(
            s,
            lambda *_: (
                log.info(f"SIGNAL {s}"),
                homekey_service.stop(),
                hap_driver.stop(),
            ),
        )

    homekey_service.start()
    hap_driver.start()


if __name__ == "__main__":
    main()
