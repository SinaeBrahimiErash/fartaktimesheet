import smtplib
from email.mime.text import MIMEText
from auth.jwt_handler import singJWT
import urllib.parse
import random

def send_reset_email(email: str, token: str):
    reset_link = f"http://localhost:8000/reset-password?token={token}"

    msg = MIMEText(f"Click the link to reset your password: {reset_link}")
    msg['Subject'] = 'Reset Your Password'
    msg['From'] = 'sinaerash@gmail.com'
    msg['To'] = email

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login('sinaerash@gmail.com', 'lwcm bzmc olld piyw')
        server.send_message(msg)
def generate_otp():
    # تولید یک عدد 6 رقمی تصادفی
    return str(random.randint(100000, 999999))