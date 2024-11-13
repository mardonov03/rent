from pydantic import BaseModel, constr, EmailStr, conint
from typing import Optional

class StolDB(BaseModel):
    stolid: conint(ge=1)
    status: constr(min_length=1)

class MenuDB(BaseModel):
    foodid: conint(ge=1)
    foodname: constr(min_length=1)
    price: conint(ge=1)


class UsersDB(BaseModel):
    userid: conint(ge=1)
    username: Optional[constr(min_length=1)] = None
    firstname: constr(min_length=1)
    lastname: Optional[constr()] = None

    stol: StolDB
    def bron_stol(self):
        return f'бронирован с: {self.userid} стол: {self.stol.stolid}'
    def unbron_stol(self):
        pass

class Admins(BaseModel):
    user: UsersDB
    menu: MenuDB
    def register_user(self):
        pass
    def delete_user(self):
        pass

    def edit_menu(self):
        pass
class Cassir(BaseModel):
    user: UsersDB

