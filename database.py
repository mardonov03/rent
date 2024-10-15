import asyncpg
import logging
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def create_pool():
    try:
        pool = await asyncpg.create_pool(
            user='postgres',
            password='dexqon.uz.com.1',
            database='rent',
            host='127.0.0.1',
            min_size=1,
            max_size=10
        )
        return pool
    except Exception as e:
        logger.error(f'create_pool error: {e}')
        return None

async def init_db(pool):
    try:
        async with pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS cars (
                    carid BIGSERIAL PRIMARY KEY,
                    carname TEXT,
                    year INTEGER,
                    color TEXT,
                    number TEXT UNIQUE,
                    photo_car BYTEA,
                    status_bron BOOLEAN DEFAULT FALSE, -- Хози брон кб койлган ёки ек
                    status_taken BOOLEAN DEFAULT FALSE, -- Хози рентга берворилган ёки ек
                    olindi TIMESTAMP,
                    price INTEGER,
                    kelishi_kerak TIMESTAMP
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    userid SERIAL PRIMARY KEY,
                    name TEXT,
                    surname TEXT,
                    patronymic TEXT,
                    username TEXT UNIQUE,
                    password TEXT,
                    gmail TEXT UNIQUE,
                    passportid TEXT UNIQUE,
                    number INTEGER,
                    age INTEGER,
                    photo BYTEA,
                    token TEXT UNIQUE, --REFRESH TOKEN
                    gmailcode TEXT,
                    countdaily INTEGER DEFAULT 0,
                    time TIMESTAMP, --кунли лимитти бошкаришчун регистрация ёки логинда
                    statuscode BOOLEAN DEFAULT FALSE, --бу код боргандан кейн почтани тасдиклаган ёки еклиги
                    account_status BOOLEAN DEFAULT FALSE, --аккаунти gmail код тасдиклагандан кейин актив клинади охрги етап бу
                    time_for_verificy_code TIMESTAMP, --верификация коди бориб тушканда койладган вохт
                    banned BOOLEAN DEFAULT FALSE, --бу мошина брон кб кемаса бан клнади passporid блан
                    bantime TIMESTAMP,
                    carid BIGINT REFERENCES cars(carid)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    userid SERIAL PRIMARY KEY,
                    name TEXT,
                    surname TEXT,
                    patronymic TEXT,
                    username TEXT UNIQUE,
                    password TEXT,
                    gmail TEXT,
                    passportid INTEGER UNIQUE,
                    age INTEGER,
                    photo BYTEA,
                    role TEXT
                )
            """)
    except Exception as e:
        logger.error(f'init_db error: {e}')

async def main():
    pool = await create_pool()
    await init_db(pool)

if __name__ == "__main__":
    asyncio.run(main())
