from fastapi import FastAPI, Path, Depends, HTTPException, status
from pydantic import BaseModel, constr, EmailStr
from typing import Annotated, Optional
import logging
from database import create_pool, init_db
from datetime import datetime, timedelta
import jwt
from fastapi.security import OAuth2PasswordBearer
import bcrypt
from fastapi import FastAPI
import uuid
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = FastAPI()

SECRET_KEY = "bgsubU_fgesgnjGREJ75428953nYBNybrg984'_2467%4#25bseaw043it"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 3

conf = ConnectionConfig(
    MAIL_USERNAME="komronmardonov233@gmail.com",
    MAIL_PASSWORD="aolg nxpr ztyp sohs",
    MAIL_FROM="komronmardonov233@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
)

class UserCreate(BaseModel):
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
    price: int

class ForverifyGmail(BaseModel):
    gmail: EmailStr
    code: str


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


async def create_jwt_token(username: str):
    expiration = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": username, "exp": expiration}, SECRET_KEY, algorithm=ALGORITHM)
    return token

async def create_refresh_token(username: str):
    expiration = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    token = jwt.encode({"sub": username, "exp": expiration}, SECRET_KEY, algorithm=ALGORITHM)
    return token

async def decode_jwt_token(token: str):
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
            user_gmail = await conn.fetchrow('SELECT gmail, account_status, statuscode FROM users WHERE gmail=$1', user.gmail)

            if user_gmail and user_gmail['account_status']:
                raise HTTPException(status_code=409, detail='Этот Gmail уже зарегистрирован. Перенаправляем на страницу входа.')
            elif user_gmail and user_gmail['statuscode']:
                hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt(rounds=12))
                token_refresh = await create_refresh_token(user.username)
                await conn.execute('UPDATE users SET username= $1, password= $2, token = $3, account_status = TRUE WHERE gmail = $4', user.username, hashed_password.decode('utf-8'), token_refresh.decode('utf-8'),user.gmail)
                token = await create_jwt_token(user.username)
                return {'token_access': token, 'token_refresh': token_refresh}
            else:
                await gmailcode(user.gmail)
    except Exception as e:
        logger.error(f'error653780345: {e}')
        raise HTTPException(status_code=500, detail='Ошибка при регистрации пользователя')

async def gmailcode(gmail):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            code = str(uuid.uuid4())[:8]
            message = MessageSchema(
                subject="Verification Code",
                recipients=[gmail],
                body=f"Ваш код подтверждения: {code}",
                subtype="html",
            )
            fm = FastMail(conf)
            try:
                await fm.send_message(message)
            except Exception as e:
                logger.error(f'Error sending email: {e}')
                raise HTTPException(status_code=500, detail='Ошибка при отправке письма.')

            hashcode = bcrypt.hashpw(code.encode('utf-8'), bcrypt.gensalt(rounds=12))
            await conn.execute('INSERT INTO users (gmail, gmailcode) VALUES ($1, $2)', gmail, hashcode.decode('utf-8'))
            return gmail
    except Exception as e:
        logger.error(f'error3242637899: {e}')

@app.post('/verify/{gmail}')
async def verify_gmail(ver: ForverifyGmail):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            status = await conn.fetchrow('SELECT account_status, gmailcode, countdaily, count, time FROM users WHERE gmail = $1', ver.gmail)
            if not status:
                raise HTTPException(status_code=404, detail='Пользователь не найден.')

            if status['account_status']:
                raise HTTPException(status_code=409, detail='Этот Gmail уже зарегистрирован. Перенаправляем на страницу входа.')

            if status['countdaily'] >= 3:
                if status['time'] < datetime.now() - timedelta(hours=24):
                    await conn.execute('UPDATE users SET count = 0, countdaily = 0 WHERE gmail=$1',ver.gmail)
                else:
                    raise HTTPException(status_code=400, detail='Вы достигли своего лимита.')

            if bcrypt.checkpw(ver.code.encode('utf-8'), status['gmailcode'].encode('utf-8')):
                await conn.execute('UPDATE users SET statuscode = TRUE, count = 0 WHERE gmail = $1', ver.gmail)
                return {"detail": "Успешно подтверждено. Перенаправляем на страницу входа."}
            else:
                await conn.execute('UPDATE users SET count = 0, countdaily = countdaily + 1 WHERE gmail=$1',ver.gmail)
                raise HTTPException(status_code=400, detail='Неверный код.')

    except Exception as e:
        logger.error(f'error98900385: {e}')
        raise HTTPException(status_code=500, detail='Ошибка при проверке кода.')



@app.post('/login')
async def handle_login(user: UserLogin):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            if not (user.username or user.gmail):
                raise HTTPException(status_code=400, detail='Необходимо указать имя пользователя или адрес электронной почты')

            if user.username:
                stored_password = await conn.fetchval('SELECT password FROM users WHERE username = $1', user.username)
                userid = await conn.fetchval('SELECT userid FROM users WHERE username =$1', user.username)
            elif user.gmail:
                stored_password = await conn.fetchval('SELECT password FROM users WHERE gmail = $1', user.gmail)
                userid = await conn.fetchval('SELECT userid FROM users WHERE gmail =$1', user.gmail)

            if stored_password:
                if bcrypt.checkpw(user.password.encode('utf-8'), stored_password.encode('utf-8')):
                    token_refresh = await create_refresh_token(user.username)
                    await conn.execute('UPDATE users SET token=$1 WHERE userid=$2', token_refresh, userid)
                    token = await create_jwt_token(user.username)
                    return {'token_access': token, 'token_refresh': token_refresh}
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
                    token = await create_jwt_token(admin.username)
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
            cars = await conn.fetch('SELECT * FROM cars WHERE status_bron=False AND status_taken =False')
            return cars
    except Exception as e:
        logger.error(f'error4363423: {e}')


@app.get('/cars/{id}')
async def handle_car(id:int):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            car = await conn.fetchval('SELECT * FROM cars WHERE carid = $1',id)
            if car:
                return car
    except Exception as e:
        logger.error(f'error342453: {e}')

