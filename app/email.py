import os

import httpx
from sqlalchemy.orm import Session

from .config import EMAIL_BACKEND, FROM_EMAIL
from .models import OutboundEmail

RESEND_API_KEY = os.getenv("RESEND_API_KEY")


def send_email(db: Session, *, to: str, subject: str, html: str) -> None:
    if EMAIL_BACKEND == "resend" and RESEND_API_KEY:
        headers = {"Authorization": f"Bearer {RESEND_API_KEY}"}
        data = {"from": FROM_EMAIL, "to": [to], "subject": subject, "html": html}
        with httpx.Client(timeout=10) as client:
            response = client.post("https://api.resend.com/emails", json=data, headers=headers)
            response.raise_for_status()
        return

    record = OutboundEmail(to_email=to, subject=subject, html=html)
    db.add(record)
    db.commit()
    print(f"[MOCK EMAIL] To: {to} | Subject: {subject}\n{html}\n")
