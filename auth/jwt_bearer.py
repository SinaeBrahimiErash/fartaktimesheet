# The goal of this file is to check whether the reques tis authorized or not [ verification of the proteced route]
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .jwt_handler import decodeJWT


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=401, detail="Invalid authentication scheme.")
            payload = decodeJWT(credentials.credentials)
            if payload and isinstance(payload, dict):
                if not self.verify_jwt(credentials.credentials):
                    raise HTTPException(status_code=401, detail="توکن شما منقضی شده است. لطفا دوباره وارد شوید.")
                return credentials.credentials
            else:
                raise HTTPException(status_code=401, detail="Invalid token or expired token.")
        else:
            raise HTTPException(status_code=401, detail="Invalid authorization code.")

    def has_role(self, payload: dict, role: str) -> bool:
        if isinstance(payload, dict):
            return payload.get('role') == role
        return False

    def verify_jwt(self, jwtoken: str) -> bool:
        try:
            payload = decodeJWT(jwtoken)
            return isinstance(payload, dict)
        except Exception as e:
            print(f"Error verifying JWT: {e}")
            return False
