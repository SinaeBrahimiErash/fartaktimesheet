from pydantic import BaseModel, validator
from typing import Optional
from enum import Enum
from typing import List


class Role(str, Enum):
    admin = 'admin'
    user = 'user'
    supervisor = 'supervisor'
    accountant = 'accountant'


class User(BaseModel):
    id: int
    UserName: str
    Name: str
    password: str
    ParentId: int = None
    role: Role


class UserUpdate(BaseModel):
    UserName: Optional[str] = None
    Name: Optional[str] = None
    password: Optional[str] = None
    parentid: float | None = None
    role: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class Time_sheet_edit(BaseModel):
    id: int
    table_name: str
    date: str
    newtime: List[str] = []


class Desciption(BaseModel):
    id: int
    table_name: str
    date: List[str] = []
    description: str


class UpdateProfile(BaseModel):
    Name: Optional[str] = None
    password: Optional[str] = None


class Time_Sheet_Status(BaseModel):
    id: int
    table_name: str
    status: bool


class total_presence(BaseModel):
    id: int
    table_name: str


class accountant_role(BaseModel):
    table_name: str
