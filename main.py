from fastapi import FastAPI, Path, Depends, HTTPException, status
from pydantic import BaseModel, constr, EmailStr
from typing import Annotated, Optional
import logging
from database import create_pool, init_db
from fastapi.responses import RedirectResponse
from datetime import datetime, timedelta
import jwt
from fastapi.security import OAuth2PasswordBearer
import bcrypt
from fastapi import FastAPI
from fastapi.middleware.wsgi import WSGIMiddleware
from django.core.wsgi import get_wsgi_application
import os
import sys
from fastapi.staticfiles import StaticFiles


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = FastAPI()

app.mount("/static", StaticFiles(directory="admin_panel/staticfiles"), name="static")

sys.path.append('admin_panel')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'admin_panel.settings')


django_app = get_wsgi_application()

app.mount("/admin", WSGIMiddleware(django_app))


SECRET_KEY = "bgsubU_fgesgnjGREJ75428953nYBNybrg984'_2467%4#25bseaw043it"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class UserCreate(BaseModel):
    userid: Optional[int] = None
    username: constr(min_length=1)
    password: constr(min_length=8)
    gmail: EmailStr

class AdminCreate(BaseModel):
    userid: Optional[int] = None
    username: constr(min_length=1)
    password: constr(min_length=8)
    gmail: EmailStr
    role: constr(min_length=1)

class UserLogin(BaseModel):
    username: Optional[constr(min_length=1)] = None
    password: constr(min_length=8)
    gmail: Optional[EmailStr] = None

class AdminLogin(BaseModel):
    username: Optional[constr(min_length=1)] = None
    password: constr(min_length=8)
    gmail: Optional[EmailStr] = None

class AddCar(BaseModel):
    carname: str
    year: int
    color: str
    number: str


@app.on_event('startup')
async def eventstart():
    try:
        pool = await create_pool()
        await init_db(pool)
    except Exception as e:
        logger.error(f'error2432556: {e}')


@app.on_event('shutdown')
async def shutdownevent():
    try:
        pool = await create_pool()
        await pool.close()
    except Exception as e:
        logger.error(f'error342553: {e}')


@app.get('/')
async def main():
    return 'hellow'


def create_jwt_token(username: str):
    expiration = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": username, "exp": expiration}, SECRET_KEY, algorithm=ALGORITHM)
    return token


def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)):
    if token is None:
        return None
    payload = decode_jwt_token(token)
    return payload


@app.post('/register', status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            user_gmail = await conn.fetchval('SELECT gmail FROM users WHERE gmail=$1', user.gmail)
            if user_gmail:
                raise HTTPException(status_code=409,detail='Этот Gmail уже зарегистрирован. Перенаправляем на страницу входа.')
            else:
                hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
                await conn.execute('INSERT INTO users (username, password, gmail) VALUES ($1, $2, $3)',user.username, hashed_password.decode('utf-8'), user.gmail)
                token = create_jwt_token(user.username)
                return {'token': token}
    except Exception as e:
        logger.error(f'error3426427624: {e}')
        raise HTTPException(status_code=500, detail='Ошибка при регистрации пользователя')

@app.post('/login')
async def handle_login(user: UserLogin):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            if not user.username and not user.gmail:
                raise HTTPException(status_code=400,detail='Необходимо указать имя пользователя или адрес электронной почты')

            if user.username:
                stored_password = await conn.fetchval('SELECT password, userid FROM users WHERE username = $1', user.username)
            elif user.gmail:
                stored_password = await conn.fetchval('SELECT password, userid FROM users WHERE gmail = $1', user.gmail)

            if stored_password:
                if bcrypt.checkpw(user.password.encode('utf-8'), stored_password.encode('utf-8')):
                    token = create_jwt_token(user.username)
                    return {'token': token}
                else:
                    raise HTTPException(status_code=401, detail='Неверный пароль')
            else:
                raise HTTPException(status_code=404, detail='Пользователь с таким именем не найден')
    except Exception as e:
        logger.error(f'error5357346335: {e}')
        raise HTTPException(status_code=500, detail='Ошибка при входе')


@app.post('/loginadmin')
async def handle_loginadmin(admin: AdminLogin):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            stored_password = await conn.fetchval('SELECT password FROM admins WHERE username = $1', admin.username)
            if stored_password:
                if bcrypt.checkpw(admin.password.encode('utf-8'), stored_password.encode('utf-8')):
                    token = create_jwt_token(admin.username)
                    return {'token': token}
                else:
                    raise HTTPException(status_code=401, detail='Неверный пароль')
            else:
                raise HTTPException(status_code=404, detail='Пользователь с таким именем не найден')
    except Exception as e:
        logger.error(f'error7432975729: {e}')
        raise HTTPException(status_code=500, detail='Ошибка при входе')



@app.get('/profile/{username}')
async def read_profile(username: str, current_user: dict = Depends(get_current_user)):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            user_data = await conn.fetchrow('SELECT userid, username, gmail FROM users WHERE username = $1', username)


            if not user_data:
                raise HTTPException(status_code=404, detail="Пользователь не найден")
            if current_user is None or user_data['userid'] != current_user['sub']:
                return {
                    "message": "Это профиль другого пользователя",
                    "profile": {
                        "userid": user_data['userid'],
                        "username": user_data['username'],
                    }
                }
            elif user_data['userid'] == current_user['sub']:
                return {
                    "message": "Это ваш профиль",
                    "profile": {
                        "userid": user_data['userid'],
                        "username": user_data['username'],
                        "gmail": user_data['gmail']
                    }
                }
    except Exception as e:
        logger.error(f'error424643265747: {e}')

@app.get('/cars')
async def handle_cars():
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            cars = await conn.fetch('SELECT * FROM cars')
            return cars
    except Exception as e:
        logger.error(f'error4363423: {e}')
