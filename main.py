from fastapi import FastAPI, Body, Depends
from enum import Enum
from pydantic import BaseModel
from typing import Annotated
import mysql.connector

cnx = mysql.connector.connect(
    user='root', password='123',
    host='127.0.0.1',
    database='test')

mycursor = cnx.cursor()
mycursor.execute('select * from Users')
data = mycursor.fetchall()
prin(data)


async def key(q: str, limit: int = 100, skip: int = 0):
    return {"q": q, "limit": limit, "skip": skip}


@app.get("/data")
async def get_data(data: Annotated[dict, Depends(key)]):
    return data


# class value(BaseModel):
#     name: str
#     fname: str
#
#
# #
# #
# # @app.get("/items/{item_id}")
# # async def root(item_id):
# #     return {"item_id": item_id}
#
# class ModelName(str, Enum):
#     alexnet = "alexnet"
#     resnet = "resnet"
#     lenet = "lenet"
#
#
# app = FastAPI()
#
#
# @app.post("/weblog")
# async def predict(weblog: value = Body()):
#     return weblog
#
#
# @app.get("/models/{model_name}")
# async def get_model(model_name: ModelName):
#     if model_name is ModelName.alexnet:
#         return {"model_name": model_name, "message": "Deep Learning FTW!"}
#
#     if model_name.value == "lenet":
#         return {"model_name": model_name, "message": "LeCNN all the images"}
#
#     return {"model_name": model_name, "message": "Have some residuals"}
#
#
# # @app.get("/users/me")
# # async def read_user_me():
# #     return {"user_id": "the current user"}
# #
# #
# #
# # @app.get("/users/{user_id}")
# # async def read_user(user_id: str):
# #     return {"user_id": user_id}
# @app.get("/users")
# async def read_users():
#     return ["Rick", "Morty"]


@app.get("/users")
async def read_users2():
    return ["Bean", "Elfo"]


fake_item_db = [{'name': "sina"}, {"name": "ALI"}, {"name": "Bob"}, {"name": "Alice"}]


@app.get("/items/")
async def read_items(skip: int = 0, limit: int = 10):
    return fake_item_db[skip:skip + limit]
