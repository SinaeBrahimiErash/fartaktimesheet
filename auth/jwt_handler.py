# this file is responsibel
import time
import jwt
from decouple import config

JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")


def token_response(token: str):
    return {
        "access_token": token
    }


def singJWT(username: str, role: str):
    payload = {
        "username": username,
        "login_time": time.time(),
        "role": role,
        "expiry": time.time() + 86400
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token_response(token)


def decodeJWT(token: str):
    try:
        decode_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if decode_token['expiry'] >= time.time():
            return decode_token
        else:
            return None
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None
