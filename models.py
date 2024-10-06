from sqlalchemy import Column, Integer, String, ForeignKey
from pydantic import BaseModel
from fastapi_admin.resources import Field, Model
from fastapi_admin.widgets import displays, inputs

# SQLAlchemy models
class User(BaseModel):
    __tablename__ = 'users'

    userid = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    gmail = Column(String, unique=True, index=True)
    password = Column(String)
    carid = Column(Integer, ForeignKey('cars.carid'))


class Admin(BaseModel):
    __tablename__ = 'admins'

    userid = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    gmail = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)


# FastAPI Admin Model for User
class UserAdmin(Model):
    fields = [
        Field("userid", label="ID", display=displays.InputOnly(), input_=inputs.DisplayOnly()),
        Field("username", label="Username", display=displays.InputOnly(), input_=inputs.Text()),
        Field("gmail", label="Gmail", display=displays.InputOnly(), input_=inputs.Email()),
    ]


# FastAPI Admin Model for Admin
class AdminAdmin(Model):
    fields = [
        Field("userid", label="ID", display=displays.InputOnly(), input_=inputs.DisplayOnly()),
        Field("username", label="Username", display=displays.InputOnly(), input_=inputs.Text()),
        Field("gmail", label="Gmail", display=displays.InputOnly(), input_=inputs.Email()),
    ]
