from enum import Enum
from uuid import UUID, uuid4
from pydantic import BaseModel
from typing import List, Optional, ClassVar
from sqlalchemy import Column, String, Integer, Enum, DateTime, TIME, Float, ForeignKey
from database import Base
import enum
from datetime import datetime
from datetime import datetime, timedelta

class Role(enum.Enum):
    admin = 'admin'
    user = 'user'
    supervisor = 'supervisor'


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    UserName = Column(String)
    Name = Column(String)
    password = Column(String)
    ParentId = Column(Integer)
    role = Column(Enum(Role))
    email = Column(String, unique=True, nullable=True)
    class Config:
        schema_extra = {
            "username": "admin",
            "name": "admin",
            "password": "123",
            "role": "admin",

        }


class UserLogin(BaseModel):
    username: str
    password: str

    class Config:
        schema_extra = {
            "user_demo": {
                "username": "admin",
                "password": "123"
            }
        }


class UserLoginHistory(Base):
    __tablename__ = "user_login_history"  # نام جدول در دیتابیس

    id = Column(Integer, primary_key=True, index=True)  # شناسه یکتا برای هر رکورد
    user_id = Column(Integer, index=True)  # شناسه کاربر
    username = Column(String, index=True)  # نام کاربری
    login_time = Column(Float)  # زمان لاگین به صورت یونیکس تایم
    logout_time = Column(Float, nullable=True)


class OTP(Base):
    __tablename__ = 'otp_codes'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    code = Column(String, nullable=False)
    expiry = Column(DateTime, nullable=False)

