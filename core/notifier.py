"""
Notifier Module
Sends system alerts and notifications to the user
"""
from plyer import notification
from logger import get_logger

log = get_logger("notifier")

MAX_LENGTH = 240  # Windows notification character limit


def alert(title, message):
    """
    Send a notification alert to the user.
    
    Args:
        title (str): Alert title (appears in bold)
        message (str): Alert message body
    """
    try:
        # Truncate message if too long for Windows notifications
        if len(message) > MAX_LENGTH:
            message = message[:MAX_LENGTH] + "..."

        notification.notify(
            title=title,
            message=message,
            timeout=5
        )
        log.info(f"Alert sent: {title}")
    except Exception as e:
        log.error(f"Error sending notification: {str(e)}")