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
from dynamic_models import create_table_from_excel

app = FastAPI()
models.Base.metadata.create_all(bind=engine)


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


class Role(str, Enum):
    admin = 'admin'
    user = 'user'


class User(BaseModel):
    id: int
    UserName: str
    Name: str
    password: str
    role: Role


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


@app.post('/api/v1/user/', tags=["Post"])
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
        raise HTTPException(status_code=404, detail="User not found")

    # بررسی نقش کاربر
    if user.role.value != "admin":
        raise HTTPException(status_code=403, detail="You do not have permission to perform this action.")
    user_model = db.query(models.User).filter(models.User.id == user_id).first()
    if user_model is None:
        raise HTTPException(status_code=404, detail=f"user with id : {user_id} does not exist")
    db.query(models.User).filter(models.User.id == user_id).delete()
    db.commit()


def hash_pass(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


@app.put("/api/v1/user/{user_id}")
async def update_user(user_id: int, user_update: User, db: Session = Depends(get_db),
                      token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user_model = db.query(models.User).filter(models.User.id == user_id).first()

    # بررسی نقش کاربر
    if user.role.value != "admin" and user.id != user_id:
        raise HTTPException(status_code=403, detail="You do not have permission to perform this action.")

    if user_model is None:
        raise HTTPException(status_code=404, detail=f"user with id : {user_id} does not exist")
    user_model.id = user_update.id
    user_model.UserName = user_update.UserName
    user_model.Name = user_update.Name
    user_model.password = hash_pass(user_update.password)
    user_model.role = user_update.role
    db.add(user_model)
    db.commit()
    return user_update


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.post('/api/v1/user', dependencies=[Depends(JWTBearer)], tags=["user"])
async def register_users(user: User, db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
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
    user_model = models.User()
    hashed_pass = hash_pass(user.password)
    user_model.id = user.id
    user_model.UserName = user.UserName
    user_model.Name = user.Name
    user_model.password = hashed_pass
    user_model.role = user.role
    db.add(user_model)
    db.commit()
    return singJWT(user.UserName)


def check_user(data: UserLogin, db: Session):
    user_model = db.query(models.User).filter(models.User.UserName == data.username).first()
    hashed_pass = hash_pass(data.password)
    if user_model and verify_password(data.password, user_model.password):
        return True
    else:
        return False


@app.post("/api/v1/user/login/", tags=["user"])
async def user_login(user: UserLogin, db: Session = Depends(get_db)):
    if check_user(user, db):
        return singJWT(user.username)
    else:
        raise HTTPException(status_code=401, detail="password not match")


# def process_data(db: Session, table_name: str):
#     try:
#         # بارگذاری جدول با استفاده از نام جدول
#         metadata = MetaData(bind=engine)
#         temp_table = Table(table_name, metadata, autoload_with=engine)
#
#         # گروه‌بندی داده‌ها بر اساس user_id و date
#         query = db.query(
#             temp_table.c.user_id,
#             temp_table.c.date,
#             func.group_concat(temp_table.c.time, ',').label('times')
#         ).group_by(temp_table.c.user_id, temp_table.c.date).all()
#
#         # اضافه کردن داده‌های گروه‌بندی شده به جدول sorted_data
#         for record in query:
#             sorted_data = models.SortedData(
#                 user_id=record.user_id,
#                 date=record.date,
#                 times=record.times
#             )
#             db.add(sorted_data)
#         db.commit()
#
#     except Exception as e:
#         db.rollback()
#         print(f"Error processing data: {str(e)}")

def process_and_delete_data(db: Session, table_name: str):
    try:
        # بارگذاری metadata بدون استفاده از پارامتر bind
        metadata = MetaData()
        # بارگذاری جدول با استفاده از نام جدول
        temp_table = Table(table_name, metadata, autoload_with=db.bind)

        # گروه‌بندی داده‌ها بر اساس user_id و date
        query = db.query(
            temp_table.c.user_id,
            temp_table.c.date,
            func.group_concat(temp_table.c.time, ',').label('times')
        ).group_by(temp_table.c.user_id, temp_table.c.date).all()

        # اضافه کردن داده‌های گروه‌بندی شده به جدول sorted_data
        for record in query:
            sorted_data = models.SortedData(
                user_id=record.user_id,
                date=record.date,
                times=record.times
            )
            db.add(sorted_data)
        db.commit()

        # حذف جدول اصلی پس از پردازش داده‌ها
        temp_table.drop(db.bind)
        db.commit()

    except Exception as e:
        db.rollback()
        print(f"Error processing and deleting data: {str(e)}")


async def read_excel(file: UploadFile):
    contents = await file.read()
    buffer = io.BytesIO(contents)
    df = pd.read_excel(buffer)
    print(df.columns)  # بررسی ستون‌ها
    print(df.head())
    return df


@app.post("/api/v1/upload_excel/", tags=["admin"])
async def upload_excel(file: UploadFile = File(...), db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
    # توکن را از JWTBearer دریافت کنید
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")
    print(payload)
    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    print(user.role.value)

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # بررسی نقش کاربر
    if user.role.value != "admin":
        raise HTTPException(status_code=403, detail="You do not have permission to perform this action.")

    try:
        filename = file.filename
        table_name = os.path.splitext(filename)[0]
        content = await file.read()
        df = pd.read_excel(io.BytesIO(content))

        metadata = MetaData()
        table = Table(
            table_name, metadata,
            Column('user_id', String),
            Column('date', String),
            Column('time', String)
        )

        metadata.create_all(bind=engine)

        for index, row in df.iterrows():
            insert_stmt = table.insert().values(
                user_id=row['id'],
                date=row['date'],
                time=row['time']
            )
            db.execute(insert_stmt)

        db.commit()
        process_and_delete_data(table_name=table_name)
        return {"message": f"File {filename} processed and data inserted into table {table_name}."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
