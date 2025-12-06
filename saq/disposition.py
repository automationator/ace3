from saq.configuration import get_config
from saq.constants import DISPOSITION_OPEN, VALID_DISPOSITIONS

# XXX refactor this

DISPOSITIONS = {}

def get_dispositions():
    return DISPOSITIONS

def initialize_dispositions():
    # initialize dispositions
    # XXX why the hell is this here?
    global DISPOSITIONS
    DISPOSITIONS = {
        DISPOSITION_OPEN: {
            "rank": 0,
            "css": "light",
            "show_save_to_event": False,
        }
    }
    for disposition in VALID_DISPOSITIONS:
        if get_config().valid_dispositions.get(disposition, False):
            DISPOSITIONS[disposition.upper()] = {
                "rank": get_config().disposition_rank.get(disposition, 0),
                "css": get_config().disposition_css.get(disposition, "special"),
                "show_save_to_event": get_config().show_save_to_event.get(disposition, False),
            }

    global BENIGN_DISPOSITIONS
    BENIGN_DISPOSITIONS = []
    for disposition in get_config().benign_dispositions:
        if get_config().benign_dispositions.get(disposition, False):
            BENIGN_DISPOSITIONS.append(disposition.upper())

    global MALICIOUS_DISPOSITIONS
    MALICIOUS_DISPOSITIONS = []
    for disposition in get_config().malicious_dispositions:
        if get_config().malicious_dispositions.get(disposition, False):
            MALICIOUS_DISPOSITIONS.append(disposition.upper())

def get_disposition_rank(disposition: str) -> int:
    return DISPOSITIONS.get(disposition, {}).get("rank", 0)

def get_malicious_dispositions() -> list[str]:
    return MALICIOUS_DISPOSITIONS
