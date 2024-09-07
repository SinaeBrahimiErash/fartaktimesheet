from enum import Enum
from uuid import UUID, uuid4
from pydantic import BaseModel
from typing import List, Optional, ClassVar
from sqlalchemy import Column, String, Integer, Enum, DateTime, TIME
from database import Base
import enum


class Role(enum.Enum):
    admin = 'admin'
    user = 'user',
    supervisor = 'supervisor'


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    UserName = Column(String)
    Name = Column(String)
    password = Column(String)
    ParentId = Column(Integer)
    role = Column(Enum(Role))

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
