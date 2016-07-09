# -*- coding: utf-8 -*-

from pg_cluster import PgCluster
import config


class PostgresPool(object):

    def __new__(cls):
        if '_inst' not in vars(cls):
            cls._inst = super(PostgresPool, cls).__new__(cls)
        return cls._inst

    def __init__(self):
        self.cluster = PgCluster(master={"host":config.HOST, "port":config.PORT},
                                 slaves=[],
                                 user=config.USER,
                                 password=config.PASSWORD)

        self._pool = self.cluster.get_threaded_pool(database=config.DATABASE)
        # self._pool = psycopg2.pool.ThreadedConnectionPool(
        #     minconn=1, maxconn=50, host=config_obj.HOST, port=config_obj.PORT,
        #     database=config_obj.DATABASE, user=config_obj.USER,  password=config_obj.PASSWORD)
        self._connection = None

    def get_cursor(self):
        try:
            if not self._connection or self._connection.closed:
                self._connection = self._pool.getconn()
            return self._connection.cursor()
        except Exception as e:
            raise
