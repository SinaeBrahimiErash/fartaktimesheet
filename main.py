import os
from sqlalchemy.exc import IntegrityError
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPAuthorizationCredentials
from dynamic_models import Role, User, UserLogin, UserUpdate, Time_sheet_edit, Desciption, UpdateProfile, \
    Time_Sheet_Status
from passlib.context import CryptContext
from typing import List
from sqlalchemy.orm import Session
from enum import Enum
from auth.jwt_bearer import JWTBearer
import models
from models import UserLoginHistory
from database import SessionLocal, engine
from auth.jwt_handler import singJWT
from auth.jwt_bearer import decodeJWT
import shutil
import pandas as pd
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Time, Table, select, update, or_, \
    Boolean
import io
from sqlalchemy import func, and_
from datetime import datetime
import time

import aiofiles
from persiantools.jdatetime import JalaliDate
import jdatetime

app = FastAPI()
models.Base.metadata.create_all(bind=engine)


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


@app.get('/api/v1/users')
async def fetch_users(db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()
    users = db.query(models.User.id,
                     models.User.UserName,
                     models.User.Name,
                     models.User.role,
                     models.User.ParentId).all()
    supervisor_list = db.query(models.User.id,
                               models.User.UserName,
                               models.User.Name,
                               models.User.role,
                               models.User.ParentId).filter(or_(
        models.User.ParentId == user.id, models.User.id == user.id)).all()

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # بررسی نقش کاربر
    if user.role.value == "admin":
        user_list = []
        for user in users:
            user_dict = {
                "id": user.id,
                "UserName": user.UserName,
                "Name": user.Name,
                "role": user.role.value,  # چون نقش به صورت Enum است، مقدار آن را استخراج می‌کنیم
                "ParentId": user.ParentId
            }
            user_list.append(user_dict)
    elif user.role.value == "supervisor":
        user_list = []
        for supervisor in supervisor_list:
            user_dict = {
                "id": supervisor.id,
                "UserName": supervisor.UserName,
                "Name": supervisor.Name,
                "role": supervisor.role.value,  # چون نقش به صورت Enum است، مقدار آن را استخراج می‌کنیم
                "ParentId": supervisor.ParentId
            }
            print(user_dict)
            user_list.append(user_dict)
    else:
        raise HTTPException(status_code=403, detail='شما به این عملیات دسترسی ندارید.')
    return user_list


@app.post('/api/v1/user/profile', tags=["Post"])
async def profile(token: str = Depends(JWTBearer()), db: Session = Depends(get_db)):
    payload = decodeJWT(token)

    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    if user is None:
        raise HTTPException(status_code=401, detail="کابر یافت نشد.")
    user_dict = {
        "id": user.id,
        "UserName": user.UserName,
        "role": user.role.value,  # چون نقش به صورت Enum است، مقدار آن را استخراج می‌کنیم
        "Name": user.Name,
        'ParentId': user.ParentId
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
    users_parent_id_is_not_none = db.query(models.User).filter(models.User.ParentId == user_id).first()

    if users_parent_id_is_not_none:
        raise HTTPException(status_code=400, detail='سرپرست دارای زیر مجموعه است .')

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
    print('salam')
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()
    print(user)
    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="کابر یافت نشد.")
    user_model = db.query(models.User).filter(models.User.id == user_id).first()
    allusername = db.query(models.User).filter(models.User.UserName == user_update.UserName).first()
    print('salam-1')
    # بررسی نقش کاربر

    if user.role.value != "admin":
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نیستید.")

    if user_model is None:
        raise HTTPException(status_code=404, detail="کابر یافت نشد.")

    if allusername:
        raise HTTPException(status_code=400, detail='نام کاربری تکراری است .')

    if user_model.role.value == "supervisor" and (
            user_update.role == "user" or user_update.role == "admin"):
        users_parent_id_is_not_none = db.query(models.User).filter(models.User.ParentId == user_id).first()
        print('salam3')
        if users_parent_id_is_not_none:
            raise HTTPException(status_code=400, detail='سرپرست دارای زیر مجموعه است .')
        print('salam4')

    if user_update.UserName:
        user_model.UserName = user_update.UserName
    if user_update.Name:
        user_model.Name = user_update.Name
    if user_update.password:
        user_model.password = hash_pass(user_update.password)
    if user_update.role:
        user_model.role = user_update.role
    if user_update.parentid:
        user_model.ParentId = user_update.parentid

    db.add(user_model)
    db.commit()
    raise HTTPException(status_code=200, detail='اظلاعات کاربر با موفقیت ویرایش شد .')


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.post('/api/v1/user/register', dependencies=[Depends(JWTBearer)], tags=["user"])
async def register_users(users: User, db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)
    if JWTBearer().has_role(payload, "admin"):

        test_id = db.query(models.User).filter(models.User.id == users.id).first()
        username = db.query(models.User).filter(models.User.UserName == users.UserName).first()
        if test_id:
            raise HTTPException(status_code=400, detail="شناسه کاربر تکراری است .")
        if username:
            raise HTTPException(status_code=400, detail='نام کاربری تکراری است .')
        if users.role.value == "supervisor":
            users.ParentId = None

        user_model = models.User()
        hashed_pass = hash_pass(users.password)
        user_model.id = users.id
        user_model.UserName = users.UserName
        user_model.Name = users.Name
        user_model.password = hashed_pass
        user_model.ParentId = users.ParentId
        user_model.role = users.role
        db.add(user_model)
        db.commit()
        raise HTTPException(status_code=200, detail='کاربر مورد نظر با موفقیت ایجاد شد')
    else:
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نمیباشید.")


def check_user(data: UserLogin, db: Session):
    user_model = db.query(models.User).filter(models.User.UserName == data.username).first()
    hashed_pass = hash_pass(data.password)
    if user_model and verify_password(data.password, user_model.password):
        return True
    else:
        return False


@app.post("/api/v1/user/login")
async def user_login(user: UserLogin, db: Session = Depends(get_db)):
    if check_user(user, db):
        db_user = db.query(models.User).filter(models.User.UserName == user.username).first()
        token_response = singJWT(user.username, db_user.role.value)

        # استخراج زمان لاگین از payload توکن
        token_payload = decodeJWT(token_response["access_token"])
        login_time = token_payload["login_time"]
        # ثبت زمان لاگین در دیتابیس
        login_history = UserLoginHistory(
            user_id=db_user.id,
            username=user.username,
            login_time=login_time
        )
        db.add(login_history)
        db.commit()

        return token_response
    else:
        raise HTTPException(status_code=400, detail="نام کاربری یا رمز عبور اشتباه است .")


async def read_and_process_excel(file: UploadFile):
    upload_directory = "uploads"
    file_path = os.path.join(upload_directory, file.filename)

    # اطمینان از وجود دایرکتوری uploads
    if not os.path.exists(upload_directory):
        os.makedirs(upload_directory)

    # ذخیره کردن فایل به صورت غیرهمزمان
    async with aiofiles.open(file_path, 'wb') as out_file:
        content = await file.read()  # خواندن محتوای فایل
        await out_file.write(content)  # نوشتن محتوای فایل در مسیر مشخص شده

    # استفاده از محتوای خوانده شده برای پردازش اکسل
    buffer = io.BytesIO(content)  # ایجاد یک buffer از محتوای فایل
    df = pd.read_excel(buffer)  # تبدیل محتوای buffer به DataFrame

    df = df.iloc[:, :3]  # انتخاب سه ستون اول
    df.columns = ['id', 'date', 'time']
    # مرتب‌سازی داده‌ها بر اساس user_id و date و time (در صورت نیاز)
    df = df.sort_values(by=['id', 'date', 'time'])

    # ادغام زمان‌ها برای هر کاربر و تاریخ
    df_grouped = df.groupby(['id', 'date'])['time'].apply(lambda x: ','.join(x.astype(str))).reset_index()

    unique_users = df_grouped['id'].unique()
    first_date_str = df_grouped['date'].iloc[0]
    first_date = JalaliDate(int(first_date_str.split('/')[0]),
                            int(first_date_str.split('/')[1]),
                            int(first_date_str.split('/')[2])).to_gregorian()
    jalali_first_date = JalaliDate.to_jalali(first_date)
    # استخراج سال و ماه شمسی
    jalali_year = jalali_first_date.year

    jalali_month = jalali_first_date.month

    if jalali_month <= 6:
        num_days_in_month = 31
    elif jalali_month <= 11:
        num_days_in_month = 30
    else:
        num_days_in_month = 29

    date_range = pd.date_range(start=JalaliDate(jalali_year, jalali_month, 1).to_gregorian(),
                               periods=num_days_in_month, freq='D')

    date_range_jalali = [JalaliDate.to_jalali(d).strftime('%Y/%m/%d') for d in date_range]

    final_data = []
    for user in unique_users:

        user_data = df_grouped[df_grouped['id'] == user]

        for date in date_range_jalali:
            description = ""
            times_edited = ""
            time_sheet_status = 0
            if date in user_data['date'].values:
                time = user_data[user_data['date'] == date]['time'].values[0]
                day_type = "0"

            else:
                time = ""

                formatted_date = date.replace('/', '-')
                jalali_date = jdatetime.date.fromisoformat(formatted_date)

                weekday = jalali_date.togregorian().weekday()

                if weekday == 3 or weekday == 4:  # پنج‌شنبه و جمعه
                    day_type = "1"
                else:
                    day_type = "0"

            # افزودن داده به لیست نهایی
            final_data.append({
                'id': user,
                'date': date,
                'time': time,
                'day_type': day_type,
                'description': description,
                'times_edited': times_edited,
                'time_sheet_status': time_sheet_status
            })

    # تبدیل لیست نهایی به DataFrame
    final_df = pd.DataFrame(final_data)

    # بررسی داده‌های نهایی برای اطمینان از درستی پردازش
    return final_df


@app.post("/api/v1/upload_excel", tags=["admin"])
async def upload_excel(file: UploadFile = File(...), db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)
    if JWTBearer().has_role(payload, "admin"):

        # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
        user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

        if user is None:
            raise HTTPException(status_code=404, detail="کابر یافت نشد.")

        try:
            df_grouped = await read_and_process_excel(file)

            # 2. درج داده‌های پردازش‌شده در دیتابیس
            table_name = os.path.splitext(file.filename)[0]

            metadata = MetaData()
            table = Table(
                table_name, metadata,
                Column('user_id', String),
                Column('date', String),
                Column('times', String),
                Column('day_type', String),
                Column('description', String),
                Column('times_edited', String),
                Column('time_sheet_status', Boolean)
            )

            metadata.create_all(bind=db.bind)

            for index, row in df_grouped.iterrows():

                try:

                    insert_stmt = table.insert().values(
                        user_id=row['id'],
                        date=row['date'],
                        times=row['time'],
                        day_type=row['day_type'],
                        description=row['description'],
                        times_edited=row['times_edited'],
                        time_sheet_status=row['time_sheet_status']
                    )
                    db.execute(insert_stmt)
                except Exception as e:
                    print(f"Failed to insert row {index}: {e} ,Data: {row}")

            db.commit()

            return HTTPException(status_code=200, detail="فایل با موفقیت آپلود شد .")

        except Exception as e:
            raise HTTPException(status_code=400, detail=f'فرمت فایل نا معتبر است: {e}')

    else:
        raise HTTPException(status_code=403, detail='شما قادر به انجام این عملیات نیستید.')


def get_table_by_name(table_name: str, db):
    # ایجاد شیء MetaData بدون آرگومان bind
    metadata = MetaData()

    # بارگذاری تمام جداول دیتابیس با استفاده از اتصال db
    metadata.reflect(bind=db.bind)

    if table_name in metadata.tables:
        table = metadata.tables[table_name]

        return table
    else:
        print(f"Table {table_name} not found")  # برای اشکال‌زدایی
        raise ValueError(f"Table {table_name} not found")


def query_data_from_table(table, user_id: str, db):
    stmt = select(table).where(table.c.user_id == user_id)

    # استفاده از Connection برای اجرای کوئری
    with db.bind.connect() as connection:
        result = connection.execute(stmt)
        return result.fetchall()


@app.post("/api/v1/time_sheet", tags=["admin"])
async def get_user_data(user_id: int, year_month: str, db: Session = Depends(get_db),
                        token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    if user is None:
        raise HTTPException(status_code=404, detail="کابر یافت نشد.")

    # بررسی نقش کاربر
    if user.role.value == "admin" or user.id == user_id or user.role.value == "supervisor":
        table_name = year_month

        try:
            table = get_table_by_name(table_name, db)

        except:
            return {"data": [], "status": {"status": ""}}

            raise HTTPException(status_code=200, detail="اطلاعاتی دریافت نشد .")

        # جستجوی داده‌ها برای user_id مشخص شده
        date = query_data_from_table(table, user_id, db)
        if len(date) == 0:
            raise HTTPException(status_code=404, detail='کاربر یافت نشد.')
        status = {"status": date[0][6]}
        arry = []
        for i in date:
            times_edited = i[5].split(',')
            times = i[2].split(',')
            if times_edited == ['']:
                times_edited = []
            if times == ['']:
                times = []
            arry.append({"id": i[0], "date": i[1], "times": times, "date_type": i[3], 'description': i[4],
                         'times_edited': times_edited})

        return {"data": arry, "status": status}
    else:
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نیستید.")


@app.post("/api/v1/edit_time_sheet", tags=["admin"])
async def edit_time_sheet(time_sheet_edit: Time_sheet_edit, db: Session = Depends(get_db),
                          token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد.")

    # دریافت داده‌ها از درخواست
    table_name = time_sheet_edit.table_name
    user_id = time_sheet_edit.id
    date = time_sheet_edit.date
    times = time_sheet_edit.newtime

    # بررسی اینکه آیا کاربر ادمین است یا ID کاربر با ID درخواستی مطابقت دارد
    if user.role.value != "admin" and user.id != user_id:
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نیستید.")
    newtime_str = ','.join(times)
    try:
        # بارگذاری متادیتا و دریافت جدول
        metadata = MetaData()
        table = Table(table_name, metadata, autoload_with=db.bind)

        # یافتن ردیفی که با user_id و date مطابقت دارد
        stmt = table.select().where(table.c.user_id == user_id).where(table.c.date == date)
        result = db.execute(stmt).fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="ردیف مورد نظر یافت نشد.")

        # بروزرسانی ستون times_edited
        update_stmt = update(table).where(table.c.user_id == user_id).where(table.c.date == date).values(

            times_edited=newtime_str)
        db.execute(update_stmt)
        db.commit()

        return {"detail": "ویرایش با موفقیت انجام شد."}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"خطا در ویرایش داده‌ها: {e}")


@app.post("/api/v1/description", tags=['admin'])
async def Add_Description(description: Desciption, db: Session = Depends(get_db),
                          token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()
    user_description = description.description
    user_id = description.id
    date = description.date
    table_name = description.table_name
    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد.")

    # دریافت داده‌ها از درخواست

    # بررسی اینکه آیا کاربر ادمین است یا ID کاربر با ID درخواستی مطابقت دارد
    if user.role.value != "admin" and user.id != user_id:
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نیستید.")

    try:
        # بارگذاری متادیتا و دریافت جدول
        metadata = MetaData()
        table = Table(table_name, metadata, autoload_with=db.bind)
        for i_data in date:
            stmt = table.select().where(table.c.user_id == user_id).where(table.c.date == i_data)

            result = db.execute(stmt).fetchone()
            if not result:
                raise HTTPException(status_code=404, detail="ردیف مورد نظر یافت نشد.")

                # بروزرسانی ستون times_edited
            update_stmt = update(table).where(table.c.user_id == user_id).where(table.c.date == i_data).values(
                description=user_description)

            db.execute(update_stmt)

        db.commit()
        return HTTPException(status_code=200, detail="توضیحات با موفقیت ثبت شد.")


    except Exception as e:
        raise HTTPException(status_code=400, detail=f"خطا در ویرایش داده‌ها: {e}")


@app.post('/api/v1/user/update_profile', dependencies=[Depends(JWTBearer)], tags=["user"])
async def update_profile(user_update: UpdateProfile, db: Session = Depends(get_db),
                         token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده با استفاده از userID از توکن
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    # بررسی اینکه آیا کاربر یافت شده است یا خیر
    if user is None:
        raise HTTPException(status_code=404, detail="کابر یافت نشد.")
    user_model = db.query(models.User).filter(models.User.id == user.id).first()

    if user_model is None:
        raise HTTPException(status_code=404, detail="کابر یافت نشد.")

    if user_update.Name:
        user_model.Name = user_update.Name
    if user_update.password:
        user_model.password = hash_pass(user_update.password)

    db.add(user_model)
    db.commit()
    raise HTTPException(status_code=200, detail='اظلاعات کاربر با موفقیت ویرایش شد.')


@app.post("/api/v1/user/logout")
async def user_logout(token: str = Depends(JWTBearer()), db: Session = Depends(get_db)):
    # توکن را بررسی و payload را استخراج کنید
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # نام کاربری را از توکن استخراج کنید
    username = payload["username"]

    # جستجوی کاربر در جدول UserLoginHistory که لاگین کرده است
    user_login_history = db.query(UserLoginHistory).filter(
        UserLoginHistory.username == username
    ).order_by(UserLoginHistory.login_time.desc()).first()

    # بررسی اینکه آیا رکوردی برای این کاربر وجود دارد یا خیر
    if user_login_history is None or user_login_history.logout_time is not None:
        raise HTTPException(status_code=404, detail="کاربر در حال حاضر لاگین نیست یا قبلاً لاگ‌اوت شده است.")

    # به‌روزرسانی زمان لاگ‌اوت
    user_login_history.logout_time = time.time()  # زمان فعلی

    # ذخیره تغییرات در دیتابیس
    db.commit()

    return {"detail": "کاربر با موفقیت لاگ‌اوت شد."}


# def unix_to_readable(unix_timestamp):
#     return datetime.fromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S')
def unix_to_readable(unix_timestamp):
    if unix_timestamp is None:
        return None  # یا می‌توانید یک مقدار پیش‌فرض دیگر مانند 'N/A' استفاده کنید
    return datetime.fromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S')


@app.get("/api/v1/admin/login-history", tags=["admin"])
async def get_login_history(db: Session = Depends(get_db), token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

    # جستجوی کاربر در پایگاه داده برای بررسی اینکه کاربر ادمین است
    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    if user.role.value != "admin":
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نیستید.")
    login_history = db.query(UserLoginHistory).all()

    # تبدیل زمان‌ها از یونیکس به فرمت قابل نمایش
    formatted_history = []
    for record in login_history:
        formatted_history.append({
            "userid": record.user_id,
            "username": record.username,
            "start_time": unix_to_readable(record.login_time),
            "end_time": unix_to_readable(record.logout_time)
        })

    return formatted_history


@app.post("/api/v1/time_sheet_status", tags=["admin"])
async def time_sheet_status(accept: Time_Sheet_Status, db: Session = Depends(get_db),
                            token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token or token expired")

    user = db.query(models.User).filter(models.User.UserName == payload["username"]).first()

    if user.role.value == "admin" or user.role.value == "supervisor":
        user_id = accept.id
        table_name = accept.table_name
        # status = accept.status

        metadata = MetaData()
        table = Table(table_name, metadata, autoload_with=db.bind)
        update_stmt = update(table).where(table.c.user_id == user_id).values(
            time_sheet_status=accept.status)
        print(update_stmt)
        db.execute(update_stmt)

        db.commit()
        return HTTPException(status_code=200, detail="تاییدیه با موفقیت ثبت شد.")

    else:
        raise HTTPException(status_code=403, detail="شما قادر به انجام این عملیات نیستید.")
