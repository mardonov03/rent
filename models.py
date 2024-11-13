from sqlalchemy import Column, Integer, String, ForeignKey, Text, Boolean, TIMESTAMP, LargeBinary

from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Car(Base):
    __tablename__ = 'cars'
    carid = Column(Integer, primary_key=True, index=True)
    carname = Column(Text)
    year = Column(Integer)
    color = Column(Text)
    number = Column(Text, unique=True)
    photo_car = Column(LargeBinary)
    status_bron = Column(Boolean, default=False)
    status_taken = Column(Boolean, default=False)
    olindi = Column(TIMESTAMP)
    price = Column(Integer)
    kelishi_kerak = Column(TIMESTAMP)
    users = relationship("User", back_populates="car")


class User(Base):
    __tablename__ = 'users'

    userid = Column(Integer, primary_key=True, index=True)
    name = Column(Text)
    surname = Column(Text)
    patronymic = Column(Text)
    username = Column(Text, unique=True, index=True)
    password = Column(Text)
    gmail = Column(Text, unique=True, index=True)
    passportid = Column(Text, unique=True)
    number = Column(Integer)
    age = Column(Integer)
    photo = Column(LargeBinary)
    token = Column(Text, unique=True)
    gmailcode = Column(Text)
    countdaily = Column(Integer, default=0)
    time = Column(TIMESTAMP)
    statuscode = Column(Boolean, default=False)
    account_status = Column(Boolean, default=False)
    time_for_verificy_code = Column(TIMESTAMP)
    banned = Column(Boolean, default=False)
    bantime = Column(TIMESTAMP)
    carid = Column(Integer, ForeignKey('cars.carid'))
    car = relationship("Car", back_populates="users")


class AdminDb(Base):
    __tablename__ = 'admins'

    userid = Column(Integer, primary_key=True, index=True)
    name = Column(Text)
    surname = Column(Text)
    patronymic = Column(Text)
    username = Column(Text, unique=True, index=True)
    password = Column(Text)
    gmail = Column(Text)
    passportid = Column(Integer, unique=True)
    age = Column(Integer)
    photo = Column(LargeBinary)
    role = Column(Text)
