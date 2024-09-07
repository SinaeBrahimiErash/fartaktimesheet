# from fastapi import Request, HTTPException
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from sqlalchemy.orm import Session
# from .auth_handler import decodeJWT  # تابع decodeJWT باید در فایل auth_handler شما تعریف شده باشد
# from .database import get_db  # تابع get_db باید در فایل database شما تعریف شده باشد
# from . import models  # مدل‌ها باید در یک فایل به نام models تعریف شده باشند
#
#
# class JWTBearer(HTTPBearer):
#     def __init__(self, auto_error: bool = True, admin_only: bool = False, user_id: int = None):
#         super(JWTBearer, self).__init__(auto_error=auto_error)
#         self.admin_only = admin_only
#         self.user_id = user_id
#
#     async def __call__(self, request: Request, db: Session = Depends(get_db)):
#         credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
#         if credentials:
#             if not credentials.scheme == "Bearer":
#                 raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
#             token = credentials.credentials
#             if not self.verify_jwt(token):
#                 raise HTTPException(status_code=403, detail="Invalid token or expired token.")
#
#             # استخراج payload و جستجوی کاربر
#             payload = decodeJWT(token)
#             user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()
#
#             if user is None:
#                 raise HTTPException(status_code=404, detail="کاربر یافت نشد.")
#
#             # بررسی نقش کاربر (admin)
#             if self.admin_only and user.role.value != "admin":
#                 raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نیستید.")
#
#             # بررسی اینکه کاربر در حال ویرایش داده‌های خودش است یا خیر
#             if self.user_id and user.id != self.user_id:
#                 raise HTTPException(status_code=403, detail="شما قادر به ویرایش این داده‌ها نیستید.")
#
#             request.state.user = user  # ذخیره کاربر در request.state برای استفاده در endpointها
#
#             return credentials.credentials
#         else:
#             raise HTTPException(status_code=403, detail="Invalid authorization code.")
#
#     def verify_jwt(self, jwtoken: str) -> bool:
#         isTokenValid: bool = False
#
#         try:
#             payload = decodeJWT(jwtoken)
#         except:
#             payload = None
#         if payload:
#             isTokenValid = True
#         return isTokenValid
