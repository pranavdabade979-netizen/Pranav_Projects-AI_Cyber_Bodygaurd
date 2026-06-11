"""
USB Monitor Module
Detects new or unauthorized USB device connections
"""
import os
import platform
import psutil
from logger import get_logger

log = get_logger("usb_monitor")

# Track previously seen USB devices
prev = set()

# Windows drive type constants
DRIVE_REMOVABLE = 2


def _is_windows_removable(drive):
    """Return True if a drive is removable on Windows."""
    if platform.system() != "Windows":
        return False
    try:
        from ctypes import windll, create_unicode_buffer

        drive_letter = os.path.splitdrive(drive)[0] + "\\"
        if not drive_letter:
            return False
        return windll.kernel32.GetDriveTypeW(drive_letter) == DRIVE_REMOVABLE
    except Exception:
        return False


def detect_usb():
    """
    Detect newly connected USB devices.

    Returns:
        list: List of new USB device paths detected since last check
    """
    global prev
    try:
        current = set()

        for p in psutil.disk_partitions(all=False):
            # Exclude main system drive and any non-removable fixed drives
            if p.device.upper().startswith("C:") or p.mountpoint.upper().startswith("C:"):
                continue

            is_removable = 'removable' in p.opts.lower() if p.opts else False
            if platform.system() == "Windows":
                # Check explicit drive type on Windows
                is_removable = is_removable or _is_windows_removable(p.device)

            if is_removable:
                current.add(p.device)

        new = current - prev

        if new:
            log.warning(f"New USB device(s) detected: {', '.join(new)}")

        prev = current
        return list(new)
    except Exception as e:
        log.error(f"Error detecting USB devices: {str(e)}")
        return []