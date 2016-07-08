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

    def _compute_result(self, files, func):
        """
        :param files: log files to process
        :param func: computing function
        :return: pandas.Series object
        """
        result = pandas.Series()

        for f in files:
            result = result.add(func(f), fill_value=0)

        return result

    def count_login(self, log_file=None):
        df = self._read_log_file(log_file)

        login = df[df.request.str.startswith("POST /v1/passport/login").fillna(False)].loc[:, ['time', 'user']]

        login['date'] = pandas.to_datetime(login.time, format="[%d/%b/%Y:%H:%M:%S").map(lambda t: t.date())

        if login.empty:
            return pandas.Series(0, index=pandas.to_datetime(df.time, format="[%d/%b/%Y:%H:%M:%S").map(lambda t: t.date()).unique())

        return login.groupby('date')['user'].nunique()

    def count_registration(self, log_file=None):
        df = self._read_log_file(log_file)

        login = df[df.request.str.startswith("POST /v1/passport/reg_user").fillna(False)]

        s = pandas.to_datetime(login.time, format="[%d/%b/%Y:%H:%M:%S")

        s = s.map(lambda t: t.date())

        return s.value_counts().sort_index()

    def analyze_log(self, computing_func):

        log_files = [f for f in os.listdir(self.log_directory) if f.startswith(self.base_log_filename)]

        return self._compute_result(log_files, computing_func)

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

        return [reg_count, login_count]

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
        self.cur.execute("SELECT COUNT(distinct compere_id), COUNT(distinct uuid) FROM income_log "
                         "WHERE date_trunc('day', send_time) = %s", (self.processing_date,))
        result = self.cur.fetchone()

        self.cur.execute("SELECT SUM(t_price) FROM income_log WHERE date_trunc('day', send_time) = %s "
                         "GROUP BY money_type ORDER BY money_type", (self.processing_date,))
        result += [i[0] for i in self.cur.fetchall()]

        return result

    def retrieve_compere_data(self):
        """
        :return: [ new compere, active compere, total_compere so far ]
        """
        self.cur.execute("SELECT COUNT(*) FROM "
                         "(SELECT rid FROM live_histories GROUP BY rid "
                         "HAVING date_trunc('day', min(start_time)) = %s) AS room_id", (self.processing_date,))
        result = self.cur.fetchone()

        self.cur.execute("SELECT COUNT(DISTINCT rid) FROM live_histories "
                         "WHERE date_trunc('day', start_time) = %s", (self.processing_date,))
        result += self.cur.fetchone()

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
        ts = int(time.mktime(self.current_hour.timetuple()))
        values = [ts, datetime.now(), self.processing_date] + self.retrieve_data()
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
    sp.run()