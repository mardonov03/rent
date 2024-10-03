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
                    carid BIGINT PRIMARY KEY,
                    carname TEXT,
                    year INTEGER,
                    color TEXT,
                    number BIGINT UNIQUE,
                    status BOOLEAN DEFAULT FALSE, -- Хози рентга берворилган ёки ек
                    olindi TIMESTAMP,
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
                    passportid INTEGER UNIQUE,
                    age INTEGER,
                    photo BYTEA,
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