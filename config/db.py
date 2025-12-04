from sqlalchemy.ext.asyncio import create_async_engine
# import ssl

# ssl_context = ssl.create_default_context(
#     cafile="/Users/toku404/Downloads/kartjis.pem"
# )


# online_engine = create_async_engine(
#     "postgresql+asyncpg://postgres:ZC4I3DnWOsS9lv2dJeEozLm4GPzMSc8V@103.127.134.84:5432/db_kartjis_core",
#     pool_size=16,
#     max_overflow=0,
#     ssl=ssl_context,
# )
from sshtunnel import SSHTunnelForwarder
from sqlalchemy.ext.asyncio import create_async_engine

# server = SSHTunnelForwarder(
#     ('103.127.134.84', 22),
#     ssh_username='kartjis',
#     ssh_pkey='/Users/toku404/Downloads/kartjis.pem',
#     remote_bind_address=('127.0.0.1', 5432),
#     local_bind_address=('127.0.0.1', 5433),
# )
# server.start()

online_engine = create_async_engine(
    "postgresql+asyncpg://toku404@127.0.0.1:5432/postgres",
    pool_size=16,
    max_overflow=0,
)


online_engine2 = create_async_engine(
    "mysql+aiomysql://root:qgQGvM8FwI9fArc2ZqY8TkvbeynQPwY1@103.127.134.84:3306", pool_size=16, max_overflow=0)
