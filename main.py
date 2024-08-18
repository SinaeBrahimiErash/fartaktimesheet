import os
from sqlalchemy.exc import IntegrityError
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import List
from sqlalchemy.orm import Session
from enum import Enum
from auth.jwt_bearer import JWTBearer
import models
from database import SessionLocal, engine
from auth.jwt_handler import singJWT
from auth.jwt_bearer import decodeJWT
import shutil
import pandas as pd
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Time, Table
import io
from sqlalchemy import func, and_
from datetime import datetime
from typing import Optional

app = FastAPI()
models.Base.metadata.create_all(bind=engine)


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


class Role(str, Enum):
    admin = 'admin',
    user = 'user'


class User(BaseModel):
    id: int
    UserName: str
    Name: str
    password: str
    role: Role


class UserUpdate(BaseModel):
    UserName: Optional[str] = None
    Name: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


@app.get('/api/v1/users')
async def fetch_users(db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # بررسی نقش کاربر
    if user.role.value != "admin":
        raise HTTPException(status_code=403, detail="You do not have permission to perform this action.")
    users = db.query(models.User.id,
                     models.User.UserName,
                     models.User.Name,
                     models.User.role).all()
    user_list = []
    for user in users:
        user_dict = {
            "id": user.id,
            "UserName": user.UserName,
            "Name": user.Name,
            "role": user.role.value  # چون نقش به صورت Enum است، مقدار آن را استخراج می‌کنیم
        }
        user_list.append(user_dict)

    return user_list


@app.post('/api/v1/user/profile', tags=["Post"])
async def profile(token: str = Depends(JWTBearer()), db: Session = Depends(get_db)):
    payload = decodeJWT(token)
    print(payload)
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()
    print(user)
    if user is None:
        raise HTTPException(status_code=401, detail="user with id  does not exist")
    user_dict = {
        "id": user.id,
        "UserName": user.UserName,
        "role": user.role.value,  # چون نقش به صورت Enum است، مقدار آن را استخراج می‌کنیم
        "Name": user.Name

    }

    return user_dict


@app.delete("/api/v1/user/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد .")

    # بررسی نقش کاربر
    if user.role.value != "admin":
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نیستید.")
    user_model = db.query(models.User).filter(models.User.id == user_id).first()
    if user_model is None:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد .")
    db.query(models.User).filter(models.User.id == user_id).delete()
    db.commit()
    raise HTTPException(status_code=200, detail='حذف با موفقیت انجام شد .')


def hash_pass(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


@app.put("/api/v1/user/{user_id}")
async def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db),
                      token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="کابر یافت نشد.")
    user_model = db.query(models.User).filter(models.User.id == user_id).first()

    # بررسی نقش کاربر
    if user.role.value != "admin" and user.id != user_id:
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نیستید.")

    if user_model is None:
        raise HTTPException(status_code=404, detail="کابر یافت نشد.")

    if user_update.UserName:
        user_model.UserName = user_update.UserName
    if user_update.Name:
        user_model.Name = user_update.Name
    if user_update.password:
        user_model.password = hash_pass(user_update.password)
    if user_update.role:
        user_model.role = user_update.role
    print(user_model)
    db.add(user_model)
    db.commit()
    return user_model


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.post('/api/v1/user/register', dependencies=[Depends(JWTBearer)], tags=["user"])
async def register_users(users: User, db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="کابر یافت نشد.")

    # بررسی نقش کاربر
    if user.role.value != "admin":
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نمیباشید.")

    test_id = db.query(models.User).filter(models.User.id == users.id).first()

    if test_id:
        return HTTPException(status_code=400, detail="شناسه کاربر تکراری است .")

    user_model = models.User()
    hashed_pass = hash_pass(users.password)
    user_model.id = users.id
    user_model.UserName = users.UserName
    user_model.Name = users.Name
    user_model.password = hashed_pass
    user_model.role = users.role
    db.add(user_model)
    db.commit()
    raise HTTPException(status_code=200, detail='کار بر مورد نظر با موفقیت ایجاد شد')

    def check_user(data: UserLogin, db: Session):
        user_model = db.query(models.User).filter(models.User.UserName == data.username).first()
        hashed_pass = hash_pass(data.password)
        if user_model and verify_password(data.password, user_model.password):
            return True
        else:
            return False


@app.post("/api/v1/user/login", tags=["user"])
async def user_login(user: UserLogin, db: Session = Depends(get_db)):
    if check_user(user, db):
        return singJWT(user.username)
    else:
        raise HTTPException(status_code=401, message="نام کاربری یا رمز عبور اشتباه است .")


async def read_and_process_excel(file: UploadFile):
    # خواندن محتویات فایل اکسل
    contents = await file.read()
    buffer = io.BytesIO(contents)

    # تبدیل محتویات به DataFrame
    df = pd.read_excel(buffer)

    # نمایش ستون‌ها و پنج ردیف اول برای بررسی
    print(df.columns)
    print(df.head())

    # مرتب‌سازی داده‌ها بر اساس user_id و date و time (در صورت نیاز)
    df = df.sort_values(by=['id', 'date', 'time'])

    # ادغام زمان‌ها برای هر کاربر و تاریخ
    df_grouped = df.groupby(['id', 'date'])['time'].apply(lambda x: ','.join(x.astype(str))).reset_index()

    print(df_grouped.head())  # نمایش داده‌های اصلاح شده

    return df_grouped


@app.post("/api/v1/upload_excel/", tags=["admin"])
async def upload_excel(file: UploadFile = File(...), db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
    # توکن را از JWTBearer دریافت کنید
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="کابر یافت نشد.")

    # بررسی نقش کاربر
    if user.role.value != "admin":
        raise HTTPException(status_code=403, detail="You do not have permission to perform this action.")
    try:
        df_grouped = await read_and_process_excel(file)

        # 2. درج داده‌های پردازش‌شده در دیتابیس
        table_name = os.path.splitext(file.filename)[0]

        metadata = MetaData()
        table = Table(
            table_name, metadata,
            Column('user_id', String),
            Column('date', String),
            Column('times', String)
        )

        metadata.create_all(bind=db.bind)

        for index, row in df_grouped.iterrows():
            insert_stmt = table.insert().values(
                user_id=row['id'],
                date=row['date'],
                times=row['time']
            )
            db.execute(insert_stmt)

        db.commit()

        return {"message": f"File {file.filename} processed and data inserted into table {table_name}."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
