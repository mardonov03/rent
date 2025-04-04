import asyncio
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Path, Depends, HTTPException, status, Request, Response, Form
from pydantic import BaseModel, constr, EmailStr,conint
from typing import Annotated, Optional
import logging
from database import create_pool, init_db
from datetime import datetime, timedelta
import jwt
from fastapi.security import OAuth2PasswordBearer
import bcrypt
import uuid
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from fastapi import HTTPException, Depends, File, UploadFile, status
from io import BytesIO
from PIL import Image
from urllib.parse import unquote
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = FastAPI()

SECRET_KEY = "bgsubU_fgesgnjGREJ75428953nYBNybrg984'_2467%4#25bseaw043ithj++@vsdv,es"
SECRET_KEY_GMAIL= 'einfiueaubdwa8bf8ybawbd87483ghgiaejw/-egw-3-aeHFbw@j39qH90Jf=ddfbe3!!'

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 30 #30

conf = ConnectionConfig(
    MAIL_USERNAME="kamronmardonov233@gmail.com",
    MAIL_PASSWORD="zbkv xlfk qnle xilt",
    MAIL_FROM="kamronmardonov233@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class UserCreate(BaseModel):
    username: constr(min_length=1)
    password: constr(min_length=8)
    gmail: EmailStr

class UserCreate_step2(BaseModel):
    name: constr(min_length=1)
    surname: constr(min_length=1)
    patronymic: constr(min_length=1)
    age: conint(ge=1)
    passportid: constr(min_length=8)

class UserLogin(BaseModel):
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
    code: constr(min_length=6)

class ForEditUser(BaseModel):
    username: constr(min_length=1)
    password: constr(min_length=8)
    name: constr(min_length=1)
    surname: constr(min_length=1)
    patronymic: constr(min_length=1)
    age: conint(ge=1)

class ColumnStructure(BaseModel):
    id: conint(ge=1)


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
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            cars = await conn.fetch('SELECT * FROM cars WHERE status_bron=False AND status_taken =False')
            return cars
    except Exception as e:
        logger.error(f'error43563: {e}')


async def create_jwt_token(username: str):
    expiration = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": username, "exp": expiration}, SECRET_KEY, algorithm=ALGORITHM)
    return token

async def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


async def create_jwt_token_gmail(username: str):
    expiration = datetime.utcnow() + timedelta(minutes=15)
    token = jwt.encode({"sub": username, "exp": expiration}, SECRET_KEY_GMAIL, algorithm=ALGORITHM)
    return token

async def decode_jwt_token_gmail(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY_GMAIL, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)):
    if token is None:
        return None
    payload = await decode_jwt_token(token)
    return payload

async def get_current_user_gmail(token: Optional[str] = Depends(oauth2_scheme)):
    if token is None:
        return None
    payload = await decode_jwt_token_gmail(token)
    return payload

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory=os.path.join(os.getcwd(), "static")), name="static")


@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})


@app.post('/register', status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, tokenuser: dict = Depends(get_current_user_gmail)):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            user_count = await conn.fetchval('SELECT COUNT(*) FROM users WHERE account_status = TRUE')

            user_gmail = await conn.fetchrow('SELECT gmail, account_status, statuscode, time_for_verificy_code FROM users WHERE gmail=$1',user.gmail)
            username = await conn.fetchrow('SELECT gmail FROM users WHERE username=$1', user.username)

            if user_gmail and user_gmail['account_status']:
                raise HTTPException(status_code=409, detail='Этот Gmail уже зарегистрирован. Перенаправляем на страницу входа.')

            if username:
                raise HTTPException(status_code=408, detail='Этот Username уже зарегистрирован. Выберите другое имя')

            if user_gmail and not user_gmail['account_status'] and not user_gmail['statuscode']:
                last_sent_time = user_gmail['time_for_verificy_code']
                if (datetime.now() - last_sent_time).total_seconds() < 60:
                    raise HTTPException(status_code=429, detail="Повторная отправка возможна не ранее чем через минуту")

            if user_gmail and user_gmail['statuscode'] and tokenuser is None:
                raise HTTPException(status_code=400, detail='Пожалуйста завершите настройку с того устройства, с которого подтвердили почту.')

            if tokenuser is not None:
                if tokenuser.get('sub') != user.gmail:
                    raise HTTPException(status_code=400, detail='Пожалуйста завершите настройку с подтвержденным gmail')
                elif user_gmail and user_gmail['statuscode'] and tokenuser.get('sub') == user.gmail:
                    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt(rounds=12))

                    role = 'superadmin' if user_count == 0 else 'user'

                    if user.gmail in ['turayevotabek195@gmail.com', 'komronmardonov23@gmail.com']:
                        role = 'admin'

                    await conn.execute('UPDATE users SET username=$1, password=$2, account_status=TRUE, gmailcode=NULL, countdaily=0, role=$4 WHERE gmail=$3', user.username, hashed_password.decode('utf-8'), user.gmail, role)
                    token = await create_jwt_token(user.username)
                    return {'token_access': token, 'gmail': user.gmail}

            gmail = await gmailcode(user.gmail)
            return f'Код подтверждения отправлен на: {gmail}'

    except HTTPException as http_err:
        raise http_err
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
            await fm.send_message(message)

            hashcode = bcrypt.hashpw(code.encode('utf-8'), bcrypt.gensalt(rounds=12))
            await conn.execute('INSERT INTO users (gmail, gmailcode, time_for_verificy_code) VALUES ($1, $2, $3) ON CONFLICT (gmail) DO UPDATE SET gmailcode = EXCLUDED.gmailcode, time_for_verificy_code = EXCLUDED.time_for_verificy_code',gmail, hashcode.decode('utf-8'), datetime.now())
            return gmail
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        logger.error(f'error3242637899: {e}')


@app.post('/verify/{gmail}',status_code=status.HTTP_201_CREATED)
async def verify_gmail(gmail: str, ver: ForverifyGmail):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            status = await conn.fetchrow('SELECT account_status, gmailcode, countdaily, time, time_for_verificy_code FROM users WHERE gmail = $1', gmail)
            if not status:
                raise HTTPException(status_code=404, detail='Пользователь не найден.')

            if status['account_status'] == True:
                raise HTTPException(status_code=409, detail='Этот Gmail уже зарегистрирован. Перенаправляем на страницу входа.')

            if status['time'] and status['time'] < datetime.now() - timedelta(hours=24):
                await conn.execute('UPDATE users SET countdaily = 0 WHERE gmail=$1', gmail)

            if status['countdaily'] >= 3:
                raise HTTPException(status_code=400, detail='Вы достигли своего лимита.')

            if status['time_for_verificy_code'] < datetime.now() - timedelta(minutes=15):
                await conn.execute('DELETE FROM users WHERE gmail = $1', gmail)
                raise HTTPException(status_code=402, detail='Срок действия кода истек')

            if bcrypt.checkpw(ver.code.encode('utf-8'), status['gmailcode'].encode('utf-8')):
                await conn.execute('UPDATE users SET statuscode = TRUE, countdaily=0, time= null, time_for_verificy_code=null WHERE gmail = $1', gmail)
                token = await create_jwt_token_gmail(gmail)
                return {"detail": "Успешно подтверждено. Перенаправляем на страницу входа.",
                        "token": token}
            else:
                await conn.execute('UPDATE users SET countdaily = countdaily + 1, time = $2 WHERE gmail=$1', gmail, datetime.now())
                raise HTTPException(status_code=400, detail='Неверный код.')
    except HTTPException as http_err:
        raise http_err

    except Exception as e:
        logger.error(f'error98900385: {e}')
        raise HTTPException(status_code=500, detail='Ошибка при проверке кода.')


@app.post('/login',status_code=status.HTTP_201_CREATED)
async def handle_login(user: UserLogin, response: Response):
    await asyncio.sleep(1)
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            if not (user.username or user.gmail):
                raise HTTPException(status_code=400, detail='Необходимо указать имя пользователя или адрес электронной почты')

            if not (user.username or user.gmail):
                raise HTTPException(status_code=400, detail="Укажите имя пользователя или email")

            if user.username:
                stored_password = await conn.fetchval('SELECT password FROM users WHERE username = $1', user.username)
                userid = await conn.fetchval('SELECT userid FROM users WHERE username =$1', user.username)
            elif user.gmail:
                stored_password = await conn.fetchval('SELECT password FROM users WHERE gmail = $1', user.gmail)
                userid = await conn.fetchval('SELECT userid FROM users WHERE gmail =$1', user.gmail)

            status = await conn.fetchrow('SELECT account_status, countdaily, time, time_for_verificy_code FROM users WHERE userid = $1', userid)
            if not status:
                raise HTTPException(status_code=404, detail='Пользователь с таким именем не найден')

            if status['account_status'] is False:
                raise HTTPException(status_code=409, detail='Аккаунт с таким именем не зараегестрирован')

            if status['time'] and status['time'] < datetime.now() - timedelta(hours=24):
                await conn.execute('UPDATE users SET countdaily = 0 WHERE userid=$1',userid)

            if status['countdaily'] >= 3:
                raise HTTPException(status_code=400, detail='Вы достигли своего лимита. попробуйте через 24 часа')

            if stored_password:
                if bcrypt.checkpw(user.password.encode('utf-8'), stored_password.encode('utf-8')):
                    token = await create_jwt_token(user.username)
                    if user.gmail in ['turayevotabek195@gmail.com', 'komronmardonov23@gmail.com','turayevotabek195%40gmail.com','komronmardonov23%40gmail.com']:
                        return {'token_access': token, 'gmail': user.gmail}
                    else:
                        return {'token_access': token}
                else:
                    await conn.execute('UPDATE users SET countdaily = countdaily + 1, time = $2 WHERE userid = $1',userid,datetime.now())
                    raise HTTPException(status_code=401, detail='Неверный пароль или имя пользователья')
    except HTTPException as http_err:
        raise http_err

    except Exception as e:
        logger.error(f'error5357346335: {e}')
        raise HTTPException(status_code=500, detail='Ошибка при входе')

def get_token_from_url(request: Request):
    token = request.query_params.get("token_access")
    return token


@app.get('/profile/{username}')
async def read_profile(request: Request, username: str, current_user: dict = Depends(get_current_user)):
    pool = await create_pool()

    token_from_url = get_token_from_url(request)

    if not token_from_url is None:
        token_from_url = await get_current_user(token_from_url)

    try:
        async with pool.acquire() as conn:
            user_data = await conn.fetchrow('SELECT * FROM users WHERE username = $1', username)

            if not user_data:
                raise HTTPException(status_code=404, detail="Пользователь не найден")

            if current_user is None and token_from_url is None:
                return {
                    "message": "Это профиль другого пользователя",
                    "profile": {
                        "userid": user_data['userid'],
                        "username": user_data['username'],
                    }
                }

            is_current_user = False
            if current_user is not None and 'sub' in current_user:
                is_current_user = user_data['username'] == current_user['sub']
            if token_from_url is not None and 'sub' in token_from_url:
                is_current_user = is_current_user or user_data['username'] == token_from_url['sub']

            if not is_current_user:
                return {
                    "message": "Это профиль другого пользователя",
                    "profile": {
                        "userid": user_data['userid'],
                        "username": user_data['username'],
                    }
                }

            return {
                "message": "Это ваш профиль",
                "profile": {
                    "userid": user_data['userid'],
                    "username": user_data['username'],
                    "name": user_data['name'],
                    "surname": user_data['surname'],
                    "patronymic": user_data['patronymic'],
                    "gmail": user_data['gmail'],
                    "passportid": user_data['passportid'],
                    "number": user_data['number'],
                    "age": user_data['age'],
                    "photo": user_data['photo'],
                    "time": user_data['time'],
                    "banned": user_data['banned'],
                    "bantime": user_data['bantime'],
                    "carid": user_data['carid'],
                }
            }

    except HTTPException as http_err:
        raise http_err

    except Exception as e:
        logger.error(f'error424643265747: {e}')
        raise HTTPException(status_code=500, detail='Внутренняя ошибка сервера')


@app.get('/profile/{username}/edit')
async def get_profile_for_edit(username: str, current_user: dict = Depends(get_current_user)):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            user_data = await conn.fetchrow('SELECT username, password, name, surname, patronymic, age FROM users WHERE username = $1', username)

            if not user_data:
                raise HTTPException(status_code=404, detail="Пользователь не найден")

            if current_user is None or user_data['username'] != current_user['sub']:
                raise HTTPException(status_code=403, detail="У вас нет прав редактировать этот профиль")
            return {
                "profile": {
                    "username": user_data['username'],
                    "name": user_data['name'],
                    "surname": user_data['surname'],
                    "patronymic": user_data['patronymic'],
                    "age": user_data['age']
                }
            }

    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        logger.error(f'error_reading_profile_for_edit: {e}')
        raise HTTPException(status_code=500, detail='Внутренняя ошибка сервера')

@app.put('/profile/{username}/edit')
async def edit_profile(user: ForEditUser, token: dict = Depends(get_current_user)):
    pool = await create_pool()
    try:
        if token is None:
            raise HTTPException(status_code=401, detail='Необходимо войти в аккаунт для редактирования профиля')

        async with pool.acquire() as conn:
            user_info = await conn.fetchrow('SELECT * FROM users WHERE gmail = $1', token['sub'])
            username_count = await conn.fetchval('SELECT COUNT(*) FROM users WHERE username = $1', user.username)
            if not user_info:
                raise HTTPException(status_code=404, detail="Пользователь не найден")

            if user_info['gmail'] != token['sub']:
                raise HTTPException(status_code=403, detail="У вас нет прав редактировать этот профиль")

            if username_count > 0:
                raise HTTPException(status_code=400, detail="Пользователь с таким username уже существует")

            await conn.execute('UPDATE users SET username=$1, password = $2, name = $3, surname=$4, patronymic = $5, age =$6, WHERE gmail=$7',user.username,user.password,user.name,user.surname,user.patronymic,user.age,token['sub'])

            logger.info(f"Пользователь {user_info['gmail']} обновил профиль")

            return {"message": "Профиль успешно обновлен"}
    except HTTPException as ht:
        raise ht
    except Exception as e:
        logger.error(f'error324468385: {e}')

@app.get('/cars')
async def handle_cars():
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            cars = await conn.fetch('SELECT * FROM cars WHERE status_bron=False AND status_taken =False')
            return cars
    except Exception as e:
        logger.error(f'error4363423: {e}')
        raise HTTPException(status_code=500, detail='Внутренняя ошибка сервера')

@app.get('/car/{id}')
async def handle_car(id:int):
    pool = await create_pool()
    try:
        async with pool.acquire() as conn:
            car = await conn.fetch('SELECT * FROM cars WHERE carid = $1',id)
            if car:
                return car
    except Exception as e:
        logger.error(f'error342453: {e}')
        raise HTTPException(status_code=500, detail='Внутренняя ошибка сервера')

@app.post('/reserve/{carid}',status_code=status.HTTP_201_CREATED)
async def reserve(carid: int, token: dict = Depends(get_current_user)):
    pool = await create_pool()
    try:
        if token is None:
            raise HTTPException(status_code=401,detail='Прежде чем забронировать машину, вам нужно зайти в свой аккаунт')

        username = token['sub']
        async with pool.acquire() as conn:
            carstat = await conn.fetchrow('SELECT status_bron, status_taken FROM cars WHERE carid = $1', carid)
            if carstat is None:
                raise HTTPException(status_code=404, detail=f'Машина с таким id не найдена')
            elif carstat['status_bron'] or carstat['status_taken']:
                raise HTTPException(status_code=400, detail=f'Эта машина уже забронирована или взята')

            user = await conn.fetchrow('SELECT userid, gmail, banned, bantime, carid, passportid FROM users WHERE username = $1', username)
            if user['passportid'] is None:
                raise HTTPException(status_code=403, detail=f'Прежде чем забронировать машину вам нужно заполнить анкету.')

            if user['banned']:
                bantime = user['bantime'] + timedelta(days=10) if user['bantime'] else None
                raise HTTPException(status_code=403, detail=f'Вы сможете забронировать машину только после: {bantime}')

            if user['carid']:
                car = await conn.fetchrow('SELECT carname, color, number, year FROM cars WHERE carid = $1',user['carid'])
                raise HTTPException(status_code=400,detail=f'Вы уже забронировали машину: {car["carname"]} {car["color"]} {car["number"]}, {car["year"]}')

            async with conn.transaction():
                await conn.execute('UPDATE users SET carid = $1 WHERE username = $2', carid, username)
                await conn.execute('UPDATE cars SET status_bron = TRUE WHERE carid = $1', carid)
                return {"message": "Машина успешно забронирована"}

    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        logger.error(f'Произошла ошибка: {e}')
        raise HTTPException(status_code=500, detail='Внутренняя ошибка сервера')

@app.post('/register_step2', status_code=status.HTTP_201_CREATED)
async def register_step2(user: UserCreate_step2, tokenuser: dict = Depends(get_current_user)):
    pool = await create_pool()
    try:
        if tokenuser is None:
            raise HTTPException(status_code=401,detail='Прежде чем забронировать машину, вам нужно зайти в свой аккаунт')
        async with pool.acquire() as conn:
            res = await conn.fetchval('SELECT gmail FROM users WHERE passportid= $1',user.passportid)
            if res:
                if res['gmail'] == tokenuser['sub']:
                    raise HTTPException(status_code=409, detail='Вы уже зарегистрированы.')
                else:
                    raise HTTPException(status_code=409, detail='Этот человек уже зарегистрирован.')
            else:
                await conn.execute('UPDATE users SET name = $1, surname = $2, patronymic = $3, age = $4, passportid = $5 WHERE gmail = $6',user.name, user.surname,user.patronymic, user.age, user.passportid, res['gmail'])
                return {"message": "Пользоваткль успешно зарегестрирован"}
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        logger.error(f'error4367894: {e}')
        raise HTTPException(status_code=500, detail='Внутренняя ошибка сервера')

@app.get('/admin')
async def admin_panel(token: dict = Depends(get_current_user)):
    try:
        pool = await create_pool()
        if token:
            async with pool.acquire() as conn:
                isadmin = await conn.fetchval('SELECT role FROM users WHERE gmail= $1', token['sub'])

                if not isadmin in ['admin', 'superadmin']:
                    raise HTTPException(status_code=401, detail="Нет прав доступа")

                tables = await conn.fetch("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
                table_list = [table['table_name'] for table in tables]

                return {"gmail": token['sub'], "tables": table_list}
        else:
            raise HTTPException(status_code=300,detail='Перенаправления на логин')

    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        logger.error(f'error0864673: {e}')

@app.get('/admin/{tablename}')
async def admin_panel_tables(tablename: str, token: dict = Depends(get_current_user)):
    pool = await create_pool()
    if token:
        try:
            async with pool.acquire() as conn:
                isadmin = await conn.fetchval('SELECT role FROM users WHERE gmail= $1', token['sub'])

                if not isadmin in ['admin', 'superadmin']:
                    raise HTTPException(status_code=401, detail="Нет прав доступа")

                columns = await conn.fetch(f'SELECT * FROM {tablename}')
                return {'columns': columns}
        except Exception as e:
            logger.error(f'error0864673: {e}')
            raise HTTPException(status_code=500, detail='Ошибка при получении данных')
    else:
        raise HTTPException(status_code=300,detail='Перенаправления на логин')

@app.get('/admin/{tablename}/{id}')
async def admin_panel_row(tablename: str, id: int, token: dict = Depends(get_current_user)):
    pool = await create_pool()
    if token:
        try:
            async with pool.acquire() as conn:
                isadmin = await conn.fetchval('SELECT role FROM users WHERE gmail= $1', token['sub'])

                if not isadmin in ['admin', 'superadmin']:
                    raise HTTPException(status_code=401, detail="Нет прав доступа")

                query = f'SELECT * FROM {tablename} WHERE {tablename[:-1]}id = $1'
                row = await conn.fetchrow(query, id)
                if not row:
                    raise HTTPException(status_code=404, detail=f"Запись с id {id} не найдена в таблице {tablename}")

                return {'data': row}
        except Exception as e:
            logger.error(f'error0864673: {e}')
            raise HTTPException(status_code=500, detail='Ошибка при получении данных')
    else:
        raise HTTPException(status_code=300,detail='Перенаправления на логин')


@app.post('/admin/{tablename}', status_code=status.HTTP_201_CREATED)
async def admin_post(tablename: str, data: dict, token: dict = Depends(get_current_user),photo: UploadFile = File(None)):
    pool = await create_pool()
    if token:
        try:
            async with pool.acquire() as conn:
                isadmin = await conn.fetchval('SELECT role FROM users WHERE gmail= $1', token['sub'])

                if not isadmin in ['admin', 'superadmin']:
                    raise HTTPException(status_code=401, detail="Нет прав доступа")

                columns = ', '.join(data.keys())
                values = ', '.join([f"${i + 1}" for i in range(len(data))])

                photo_data = None
                if photo:
                    image = Image.open(photo.file)
                    with BytesIO() as byte_io:
                        image.save(byte_io, format="PNG")
                        photo_data = byte_io.getvalue()

                query = f"INSERT INTO {tablename} ({columns}) VALUES ({values})"

                if photo_data:
                    data['photo_car'] = photo_data

                await conn.execute(query, *data.values())

                return {"detail": "Record inserted successfully"}

        except Exception as e:
            logger.error(f'error0864673: {e}')
            raise HTTPException(status_code=500, detail='Ошибка при добавлении данных')
    else:
        raise HTTPException(status_code=300,detail='Перенаправления на логин')


@app.put('/admin/{tablename}/{id}')
async def admin_update(tablename: str, id: int, data: dict, token: dict = Depends(get_current_user)):
    pool = await create_pool()
    if token:
        try:
            async with pool.acquire() as conn:
                isadmin = await conn.fetchval('SELECT role FROM users WHERE gmail= $1', token['sub'])

                if not isadmin in ['admin', 'superadmin']:
                    raise HTTPException(status_code=401, detail="Нет прав доступа")

                set_clause = ', '.join([f"{key} = ${i+1}" for i, key in enumerate(data.keys())])
                values = list(data.values())
                values.append(id)

                query = f"UPDATE {tablename} SET {set_clause} WHERE {tablename[:-1]}id = ${len(values)}"
                await conn.execute(query, *values)

                return {"detail": "Record updated successfully"}
        except Exception as e:
            logger.error(f'error0864673: {e}')
            raise HTTPException(status_code=500, detail='Ошибка при обновлении данных')
    else:
        raise HTTPException(status_code=300,detail='Перенаправления на логин')
