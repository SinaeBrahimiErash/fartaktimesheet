from sqlalchemy import MetaData, Table, Column, Integer, String, DateTime
from database import engine
import os

metadata = MetaData()

def create_table_from_excel(file_name):
    table_name = os.path.splitext(file_name)[0]
    table = Table(
        table_name, metadata,
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('userid', String),
        Column('date', DateTime),
        Column('time', String),
    )
    metadata.create_all(engine)  # ایجاد جداول در پایگاه داده
    return table