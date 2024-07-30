from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Enum
from sqlalchemy.orm import relationship
import enum
from .engine import Base


class roleenum(enum.Enum):
    admin = 'admin'
    user = 'user'


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    UserName = Column(String, unique=True, index=True)
    Name = Column(String)
    password = Column(String, unique=True, index=True)
    role = Column(Enum(roleenum))
