# -*- coding: utf-8 -*-
# __author__ = 'billy'

import random
import psycopg2.pool
import psycopg2

class PgCluster:
    def __init__(self, master, slaves, user='postgres', password=None):
        if master is None:
            raise Exception("parameter master's value invalid")
        if isinstance(master, dict):
            if 'host' in master:
                host = master['host']
                if 'port' in master:
                    port = master['port']
                else:
                    port = 5432
            else:
                raise Exception("parameter master's value invalid")
        elif isinstance(master, str):
            sep = master.find(':')
            if sep > 0:
                host = master[:sep]
                port = master[sep:]
            else:
                host = master
                port = 5432
        self.master = {'host': host, 'port': port}
        self.slaves = []
        if isinstance(slaves, list):
            for slave in slaves:
                if 'host' in slave:
                    if 'port' in slave:
                        port = slave['port']
                    else:
                        port = 5432
                    self.slaves.append({'host': slave['host'], 'port': port})
        elif isinstance(slaves, str):
            for slave in slaves.split(','):
                sep = slave.find(':')
                if sep > 0:
                    host = slave[:sep]
                    port = slave[sep:]
                else:
                    host = slave
                    port = 5432
                self.slaves.append({'host': host, 'port': port})
        self.user = user
        self.password = password
        pass

    def __check_node__(self, host, port=5432, master=True):
        conn = psycopg2.connect(host=host, port=port, user=self.user, password=self.password)
        cur = conn.cursor()
        try:
            cur.execute('SELECT pg_is_in_recovery()')
            res = cur.fetchone()
            if master:
                return res == (False,)
            else:
                return res == (True,)
        except Exception, e:
            return False
        finally:
            cur.close()
            conn.close()

    def discover_master(self):
        host = self.master['host']
        port = self.master['port']
        if not self.__check_node__(self.master['host'], self.master['port']):
            for slave in self.slaves:
                if self.__check_node__(slave['host'], slave['port']):
                    self.slaves.append({'host': self.master['host'], 'port': self.master['port']})
                    self.master['host'] = slave['host']
                    self.master['port'] = slave['port']
                    self.slaves.remove(self.slaves.index(slave))
                    host = slave['host']
                    port = slave['port']
                    break
        if host is None:
            raise Exception('master unavailable')
        return host, port

    def discover_slave(self):
        count = len(self.slaves)
        if count == 1:
            if self.__check_node__(self.slaves[0]['host'], self.slaves[0]['port'], False):
                return self.slaves[0]['host'], self.slaves[0]['port']
        elif count > 1:
            random.shuffle(self.slaves)
            for slave in self.slaves:
                if self.__check_node__(slave['host'], slave['port'], False):
                    return slave['host'], slave['port']
        if not self.__check_node__(self.master['host'], self.master['port']):
            raise Exception('server unavailable')
        return self.master['host'], self.master['port']

    def get_connection(
            self, dsn=None, database=None, user=None, password=None, master=True, connection_factory=None,
            cursor_factory=None, async=None, **kwargs):
        if master:
            host, port = self.discover_master()
        else:
            host, port = self.discover_slave()
        return psycopg2.connect(dsn, database, user, password, host, port, connection_factory, cursor_factory,
                                async, **kwargs)

    def get_simple_pool(
            self, database=None, user=None, password=None, master=True, minconn=1, maxconn=20):
        if master:
            host, port = self.discover_master()
        else:
            host, port = self.discover_slave()
        return psycopg2.pool.SimpleConnectionPool(
            minconn, maxconn, host=host, port=port, database=database, user=self.user if user is None else user,
            password=self.password if password is None else password)

    def get_threaded_pool(
            self, database=None, user=None, password=None, master=True, minconn=1, maxconn=20):
        if master:
            host, port = self.discover_master()
        else:
            host, port = self.discover_slave()
        return psycopg2.pool.ThreadedConnectionPool(
            minconn, maxconn, host=host, port=port, database=database, user=self.user if user is None else user,
            password=self.password if password is None else password)