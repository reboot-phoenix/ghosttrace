from modules.name import check_name
from modules.phone import check_phone
from modules.email import check_email


def scan(scan_type, query):
    """
    Main OSINT dispatcher.
    Every module returns:
        results, score, summary
    """

    scan_type = scan_type.lower().strip()

    scanners = {
        "name": check_name,
        "phone": check_phone,
        "email": check_email,
    }

    if scan_type not in scanners:
        raise ValueError(f"Unsupported scan type: {scan_type}")

    return scanners[scan_type](query)
