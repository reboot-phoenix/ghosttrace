from modules.username import check_username
from modules.phone import check_phone


def scan(scan_type, query):
    """
    Main OSINT dispatcher.
    Every module returns:
        results, score, summary
    """

    scan_type = scan_type.lower().strip()

    scanners = {
        "username": check_username,
        "phone": check_phone,
    }

    if scan_type not in scanners:
        raise ValueError(f"Unsupported scan type: {scan_type}")

    return scanners[scan_type](query)
