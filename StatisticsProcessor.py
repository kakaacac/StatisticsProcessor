#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import os
import gzip
from datetime import datetime, timedelta
import pandas
from functools import wraps

from pg_pool import PostgresPool
import config

class StatisticsProcessor(object):
    def __init__(self, log_file=None, log_directory=None, processing_time=None):
        now = datetime.now()
        current_hour = now.replace(minute=0, second=0, microsecond=0)
        if processing_time:
            if processing_time.replace(minute=0, second=0, microsecond=0) > current_hour:
                raise ValueError("Invalid processing time")
            else:
                self.processing_time = processing_time
        else:
            self.processing_time = now

        self.current_hour = self.processing_time.replace(minute=0, second=0, microsecond=0)
        self.processing_date = self._get_processing_date()

        self.connection = PostgresPool()
        self.cur = self.connection.get_cursor()

        self.log_file = log_file
        self.log_directory = log_directory or config.LOG_DIRECTORY
        self.base_log_filename = config.BASE_LOG_FILENAME

    def _get_processing_date(self):
        """
        If before 1:00am, process data of last day
        """
        return self.processing_time.date() - timedelta(1) if self.current_hour.hour == 0 else self.processing_time.date()

    def _open_log_file(self, file_name=None):
        if file_name.endswith(".gz"):
            return gzip.open(os.path.join(self.log_directory, file_name))
        else:
            return open(os.path.join(self.log_directory, file_name))

    def _read_log_file(self, file_name=None):
        """
        read the file into a pandas Dataframe and return it
        """
        fn = file_name or self.log_file
        # return pandas.read_csv(fn,
        return pandas.read_csv(self._open_log_file(fn),
                               sep = ' ',
                               quotechar='"',
                               names=["ip_addr", "bar", "user", "time", "timezone", "request", "status",
                                      "body_size", "http_referrer", "user_agent", "forwarded"],
                               index_col=False)

    def summarize_login(self, df=None):
        login = df[df.request.str.startswith("POST /v1/passport/login").fillna(False)
                   & (df.status==200)].loc[:, ['time', 'user']]

        login['date'] = pandas.to_datetime(login.time, format="[%d/%b/%Y:%H:%M:%S").map(lambda t: t.date())

        if login.empty:
            return pandas.Series(0, index=pandas.to_datetime(df.time, format="[%d/%b/%Y:%H:%M:%S").map(lambda t: t.date()).unique())

        return login.groupby('date')['user'].nunique()

    def summarize_registration(self, df=None):
        login = df[df.request.str.startswith("POST /v1/passport/reg_user").fillna(False)
                   & (df.status==200)]

        s = pandas.to_datetime(login.time, format="[%d/%b/%Y:%H:%M:%S")

        s = s.map(lambda t: t.date())

        return s.value_counts().sort_index()

    def summarize_auth_data(self):
        log_files = [f for f in os.listdir(self.log_directory) if f.startswith(self.base_log_filename)]

        reg = pandas.Series()
        login = pandas.Series()

        for f in log_files:
            df = self._read_log_file(f)
            reg = reg.add(self.summarize_registration(df), fill_value=0)
            login = login.add(self.summarize_login(df), fill_value=0)

        data = pandas.concat([reg, login], axis=1).rename(columns={0:'reg', 1:'login'}).fillna(0)
        data.index = data.index.tz_localize(psycopg2.tz.FixedOffsetTimezone(offset=480, name=None))
        return data

    def summarize_recharging_data(self):
        self.cur.execute("SELECT COUNT(distinct uuid), COALESCE(SUM(money), 0), date_trunc('day', complete_time) AS d "
                         "FROM payment_history GROUP BY d ORDER BY d")

        return pandas.DataFrame(self.cur.fetchall(), columns=["user", "amount", "date"]).set_index("date")

    def _sql_to_df(self, query):
        self.cur.execute(query)
        return pandas.DataFrame(self.cur.fetchall()).rename(columns={0:'date'}).set_index('date')

    def summarize_compere_data(self):
        new_query = "SELECT d, COUNT(rid) FROM " \
                    "(SELECT date_trunc('day', MIN(start_time)) AS d, rid FROM live_histories GROUP BY rid) AS t " \
                    "GROUP BY d ORDER BY d"
        new = self._sql_to_df(new_query)

        active_query = "SELECT date_trunc('day', start_time) AS d, COUNT(DISTINCT rid) FROM live_histories GROUP BY d"
        active = self._sql_to_df(active_query)

        total_query = "SELECT d, COUNT(DISTINCT rid) FROM live_histories l INNER JOIN " \
                      "(SELECT DISTINCT date_trunc('day', start_time) d FROM live_histories) AS dates " \
                      "ON date_trunc('day', l.start_time) <= dates.d GROUP BY dates.d"
        total = self._sql_to_df(total_query)

        data = pandas.concat([new, active, total], axis=1)
        data.columns = ['new', 'active', 'total']
        return data

    def summarize_props_giving_data(self):
        user_query = "SELECT date_trunc('day', send_time) d, COUNT(distinct compere_id), COUNT(distinct uuid) " \
                "FROM income_log GROUP BY d"
        user = self._sql_to_df(user_query)

        amount_query = "SELECT date_trunc('day', send_time) d, money_type t, SUM(t_price) FROM income_log " \
                       "GROUP BY d, t ORDER BY d, t"

        # vcy, vfc
        self.cur.execute(amount_query)
        amount = pandas.DataFrame(self.cur.fetchall()).rename(columns={0:'date', 1:'type', 2:'amount'}).set_index(['date', 'type']).unstack(1)
        amount.columns = amount.columns.get_level_values(1)

        data = pandas.concat([user, amount], axis=1)
        data.columns = ['recipient', 'presenter'] + data.columns[2:].tolist()
        return data

    def summarize_data(self):
        return self.summarize_compere_data() + \
               self.summarize_props_giving_data() + \
               self.summarize_auth_data() + \
               self.summarize_recharging_data()

    # TODO: raise error if no log file found
    def _get_corresponding_log_files(self):
        """
        :return: list of log files containing data of processing day
        """
        d = self.processing_date
        next_d = d + timedelta(1)
        d_fn = self.base_log_filename + '-' + d.strftime("%Y%m%d") + '.gz'
        nd_fn = self.base_log_filename + '-' + next_d.strftime("%Y%m%d") + '.gz'

        if os.path.exists(os.path.join(self.log_directory, d_fn)):
            if os.path.exists(os.path.join(self.log_directory, nd_fn)):
                return [d_fn, nd_fn]
            else:
                return [d_fn, self.base_log_filename]
        else:
            return [self.base_log_filename]

    def retrieve_auth_data(self):
        """
        :return: [ num of registration, num of login ]
        """
        reg_count = 0
        login_count = 0
        for log in self._get_corresponding_log_files():
            df = self._read_log_file(log)
            login = df[(df.request.str.startswith("POST /v1/passport/login").fillna(False))
                       & (df.status==200)].loc[:, ['time', 'user']]
            reg = df[(df.request.str.startswith("POST /v1/passport/reg_user").fillna(False))
                     & (df.status==200)].loc[:, ['time', 'user']]

            login['date'] = pandas.to_datetime(login.time, format="[%d/%b/%Y:%H:%M:%S").map(lambda t: t.date())
            reg['date'] = pandas.to_datetime(reg.time, format="[%d/%b/%Y:%H:%M:%S").map(lambda t: t.date())

            reg_count += len(reg[reg.date == self.processing_date].user.unique())
            login_count += len(login[login.date == self.processing_date].user.unique())

        return reg_count, login_count

    def retrieve_recharging_data(self):
        """
        :return: [ num of user, total amount ]
        """
        self.cur.execute("SELECT COUNT(distinct uuid), COALESCE(SUM(money), 0) FROM payment_history "
                         "WHERE date_trunc('day', complete_time) = %s", (self.processing_date,))
        return self.cur.fetchone()

    def retrieve_props_giving_data(self):
        """
        :return: [ num of presenter, num of recipient, vcy, vfc ]
        """
        # num of presenter, num of recipient
        self.cur.execute("SELECT COUNT(distinct compere_id), COUNT(distinct uuid) FROM income_log "
                         "WHERE date_trunc('day', send_time) = %s", (self.processing_date,))
        result = self.cur.fetchone()

        # vcy, vfc
        self.cur.execute("SELECT SUM(t_price) FROM income_log WHERE date_trunc('day', send_time) = %s "
                         "GROUP BY money_type ORDER BY money_type", (self.processing_date,))
        result += tuple(i[0] for i in self.cur.fetchall())

        return result

    def retrieve_compere_data(self):
        """
        :return: [ new compere, active compere, total_compere so far ]
        """
        # new compere
        self.cur.execute("SELECT COUNT(*) FROM "
                         "(SELECT rid FROM live_histories GROUP BY rid "
                         "HAVING date_trunc('day', min(start_time)) = %s) AS room_id", (self.processing_date,))
        result = self.cur.fetchone()

        # active compere
        self.cur.execute("SELECT COUNT(DISTINCT rid) FROM live_histories "
                         "WHERE date_trunc('day', start_time) = %s", (self.processing_date,))
        result += self.cur.fetchone()

        # total_compere so far
        self.cur.execute("SELECT COUNT(DISTINCT rid) FROM live_histories "
                         "WHERE date_trunc('day', start_time) <= %s", (self.processing_date,))
        result += self.cur.fetchone()

        return result

    def retrieve_data(self):
        return self.retrieve_compere_data() + \
               self.retrieve_props_giving_data() + \
               self.retrieve_auth_data() + \
               self.retrieve_recharging_data()

    def run(self, on_conflict=False):
        """
        :param on_conflict: if Ture, will update rows if conflict occurs
        """
        ts = int(time.mktime(self.current_hour.timetuple()))
        values = (ts, datetime.now(), self.processing_date) + self.retrieve_data()
        insert_str = ','.join(["%s"]*len(values)).join(['(', ')'])
        query = "INSERT INTO daily_statistics VALUES " + insert_str

        if on_conflict:
            conflict_str = " ON CONFLICT (id) DO UPDATE SET " \
                           "(id, update_time, processing_date, new_compere, " \
                           "active_compere, total_compere, recipient, " \
                           "presenter, vcy_received, vfc_received, user_registered, " \
                           "uesr_logined, user_recharged, recharged_amount) = " + insert_str
            query += conflict_str
            values = values*2

        self.cur.execute(query, values)
        self.cur.connection.commit()


def timing(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        start = time.time()
        result = f(*args, **kwargs)
        end = time.time()
        print 'func:%r took: %2.4f sec' % (f.__name__, end - start)
        return result
    return wrap


if __name__ == '__main__':
    sp = StatisticsProcessor()

    # df = pandas.DataFrame(sp.summarize_recharging_data(), columns=["user", "amount", "date"]).set_index("date")
    # print df

    # print sp.summarize_compere_data()
    # print sp.summarize_compere_data().index
    print sp.summarize_auth_data().index
