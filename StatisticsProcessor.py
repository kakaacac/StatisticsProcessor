#!/usr/bin/env python
# -*- coding: utf-8 -*-

import psycopg2
import time
import os
import sys
import gzip
from datetime import datetime, timedelta
import pandas
from functools import wraps

from pg_pool import PostgresPool
from logger import logger
import config

# TODO: update summarizing functions for newly added data
# TODO: make it more flexible for adding other stats in future (e.g. separate SQL and codes)
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

        self.pg_pool = PostgresPool()
        self.cur = self.pg_pool.get_cursor()

        self.log_file = log_file
        self.log_directory = log_directory or config.LOG_DIRECTORY
        self.base_log_filename = config.BASE_LOG_FILENAME

        self.start_date = None
        self._df = None
        self._logs = None
        self.current_log = self._get_current_day_log()

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
        return pandas.read_csv(self._open_log_file(fn),
                               sep = ' ',
                               quotechar='"',
                               names=["ip_addr", "bar", "user", "time", "timezone", "request", "status",
                                      "body_size", "http_referrer", "user_agent", "forwarded"],
                               index_col=False)

    def _get_df(self, log_files, request=None, regex=False):
        if self._df is not None and self._logs == log_files:
            temp_df = self._df
        else:
            temp_df = pandas.DataFrame()
            for log in log_files:
                temp_df = pandas.concat([temp_df, self._read_log_file(log)])

            temp_df['time'] = pandas.to_datetime(temp_df['time'], format="[%d/%b/%Y:%H:%M:%S")
            temp_df['date'] = temp_df['time'].map(lambda t: t.date())

            self._df = temp_df
            self._logs = log_files

        if request:
            if regex:
                r = request if request.startswith("^") else "^{}".format(request)
                regex_filter = lambda df, request: df[(df.request.str.contains(request).fillna(False))
                                                      & (df.status==200)].loc[:, ['time', 'user', 'date']]
                df = regex_filter(temp_df, r)
            else:
                str_filter = lambda df, request: df[(df.request.str.startswith(request).fillna(False))
                                                    & (df.status==200)].loc[:, ['time', 'user', 'date']]
                df = str_filter(temp_df, request)
        else:
            df = temp_df

        return df

    def _get_all_auth_data(self, log_files):
        """
        :return: two Dataframes containing all log records of registration and login, respectively
        """
        reg = self._get_df(log_files, request="POST /v1/passport/reg_user")
        login = self._get_df(log_files, request="POST /v1/passport/login")

        return reg, login

    def summarize_auth_data(self, log_constraint=True):
        """
        :param log_constraint: if True, omit first row of data since it contains uncompleted daily stats
        """
        log_files = [f for f in os.listdir(self.log_directory) if f.startswith(self.base_log_filename)]

        reg, login = self._get_all_auth_data(log_files)

        reg = reg.groupby('date')['user'].count()
        login = login.groupby('date')['user'].nunique()

        data = pandas.concat([reg, login], axis=1).fillna(0)
        data.index = pandas.DatetimeIndex(data.index, tz=psycopg2.tz.FixedOffsetTimezone(offset=480, name=None))
        data.columns = ['reg', 'login']

        self.start_date = data.index[1]

        return data.iloc[1:] if log_constraint else data

    def summarize_recharging_data(self):
        # num of user, total amount
        self.cur.execute("SELECT COUNT(distinct uuid), COALESCE(SUM(money), 0), "
                         "date_trunc('day', complete_time + INTERVAL '8 HOUR') AS d "
                         "FROM payment_history GROUP BY d ORDER BY d")

        data = pandas.DataFrame(self.cur.fetchall(), columns=["user", "amount", "date"]).set_index("date")
        data.index = data.index.tz_localize(psycopg2.tz.FixedOffsetTimezone(offset=480, name=None))

        return data

    def _sql_to_df(self, query):
        self.cur.execute(query)
        return pandas.DataFrame(self.cur.fetchall()).rename(columns={0:'date'}).set_index('date')

    def summarize_compere_data(self):
        # new_compere
        new_query = "SELECT d, COUNT(rid) FROM " \
                    "(SELECT date_trunc('day', MIN(start_time)) AS d, rid FROM live_histories GROUP BY rid) AS t " \
                    "GROUP BY d ORDER BY d"
        new = self._sql_to_df(new_query)

        # active_compere
        active_query = "SELECT date_trunc('day', start_time) AS d, COUNT(DISTINCT rid) FROM live_histories GROUP BY d"
        active = self._sql_to_df(active_query)

        # total_compere
        total_query = "SELECT d, COUNT(DISTINCT rid) FROM live_histories l INNER JOIN " \
                      "(SELECT DISTINCT date_trunc('day', start_time) d FROM live_histories) AS dates " \
                      "ON date_trunc('day', l.start_time) <= dates.d GROUP BY dates.d"
        total = self._sql_to_df(total_query)

        data = pandas.concat([new, active, total], axis=1)
        data.columns = ['new', 'active', 'total']
        return data

    def summarize_props_giving_data(self):
        # recipient, presenter
        user_query = "SELECT date_trunc('day', send_time) d, COUNT(distinct compere_id), COUNT(distinct uuid) " \
                "FROM income_log GROUP BY d"
        user = self._sql_to_df(user_query)

        # vcy, vfc
        amount_query = "SELECT date_trunc('day', send_time) d, money_type t, SUM(t_price) FROM income_log " \
                       "GROUP BY d, t ORDER BY d, t"
        self.cur.execute(amount_query)
        amount = pandas.DataFrame(self.cur.fetchall()).rename(columns={0:'date', 1:'type', 2:'amount'}).set_index(['date', 'type']).unstack(1)
        amount.columns = amount.columns.get_level_values(1)

        data = pandas.concat([user, amount], axis=1)
        data.columns = ['recipient', 'presenter'] + data.columns[2:].tolist()
        data.index = data.index.tz_localize(psycopg2.tz.FixedOffsetTimezone(offset=480, name=None))
        return data

    def summarize_data(self, log_constraint=True):
        """
        :param log_constraint: if True, return data after the date on which log file begins
        """
        result = pandas.concat([self.summarize_compere_data(),
                                self.summarize_props_giving_data(),
                                self.summarize_auth_data(),
                                self.summarize_recharging_data()], axis=1).fillna(0)

        return result.loc[self.start_date:] if log_constraint else result

    # TODO: raise error if no log file found
    def _get_current_day_log(self):
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

    @staticmethod
    def parse_auth(auth):
        if "." in auth:
            identity = auth.split(".")[1]
        else:
            identity = auth.rsplit("-", 1)[1]
        return identity

    def retrieve_auth_data(self):
        """
        :return: [ num of registration, num of login ]
        """
        reg, login = self._get_all_auth_data(self.current_log)
        reg.user = reg.user.apply(self.parse_auth)
        login.user = login.user.apply(self.parse_auth)

        return len(reg[reg.date == self.processing_date].user.unique()), \
               len(login[login.date == self.processing_date].user.unique())

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

        # vcy
        self.cur.execute("SELECT COALESCE(SUM(t_price), 0) FROM income_log "
                         "WHERE money_type='vcy' AND date_trunc('day', send_time) = %s", (self.processing_date,))
        result += self.cur.fetchone()

        # vfc
        self.cur.execute("SELECT COALESCE(SUM(t_price), 0) FROM income_log "
                         "WHERE money_type='vfc' AND date_trunc('day', send_time) = %s", (self.processing_date,))
        result += self.cur.fetchone()

        return result

    def retrieve_compere_data(self):
        """
        :return: [ new compere, active compere, total_compere so far, normal, paid,
                    interactive live show, cheating dice, Q&A ]
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

        # total live show, normal, paid
        self.cur.execute("SELECT COUNT(*) FROM live_histories WHERE date_trunc('day', start_time) = %s GROUP BY type ORDER BY type", (self.processing_date,))
        r = self.cur.fetchall()
        normal = r[0][0]
        paid = r[1][0]
        result += (normal, paid)

        # number of interactive live show
        self.cur.execute("SELECT COUNT(*) FROM live_histories WHERE (start_time, rid) IN "
                         "(SELECT start_time, rid FROM live_histories lh INNER JOIN game_bonus_stats gs "
                         "ON lh.rid = gs.room_id AND gs.game_start >= lh.start_time "
                         "AND gs.game_end <= lh.close_time WHERE date_trunc('day', start_time) = %s "
                         "GROUP BY start_time, rid)", (self.processing_date,))
        result += self.cur.fetchone()

        # number of cheating dice and Q&A
        self.cur.execute("SELECT game_id, COUNT(*) FROM game_bonus_stats WHERE date_trunc('day', game_start) = %s and game_id IS NOT NULL GROUP BY game_id", (self.processing_date,))

        r = reduce(lambda x, y: x.update({y[0]: y[1]}) or x, self.cur.fetchall(), {})
        result += (r.get(1, 0), r.get(2, 0))

        return result

    def retrieve_data(self):
        return self.retrieve_compere_data() + \
               self.retrieve_props_giving_data() + \
               self.retrieve_auth_data() + \
               self.retrieve_recharging_data()

    def summarize(self):
        now = datetime.now()

        values = ()
        query = "INSERT INTO daily_statistics VALUES "
        df = self.summarize_data()

        query += ','.join(['(' + ','.join(['%s']*14) + ')']*len(df))

        for index, data in df.iterrows():
            id = index.value // 10**9
            values += (id, now, index) + zip(*data.iteritems())[1]

        self.cur.execute(query, values)
        self.cur.connection.commit()

    def run(self):
        ts = int(time.mktime(self.processing_date.timetuple()))
        retrieved_values = self.retrieve_data()
        values = (ts, datetime.now(), self.processing_date) + retrieved_values
        insert_str = ','.join(["%s"]*len(values)).join(['(', ')'])
        query = "INSERT INTO daily_statistics (id, update_time, processing_date, new_compere, active_compere, " \
                "total_compere, normal_show, paid_show, interactive_show, cheating_dice, qna, recipient, presenter, " \
                "vcy_received, vfc_received, user_registered, uesr_logined, user_recharged, recharged_amount) " \
                "VALUES " + insert_str

        conflict_str = " ON CONFLICT (id) DO UPDATE SET " \
                       "(id, update_time, processing_date, new_compere, active_compere, total_compere, " \
                       "normal_show, paid_show, interactive_show, cheating_dice, qna, recipient, presenter, " \
                       "vcy_received, vfc_received, user_registered, uesr_logined, " \
                       "user_recharged, recharged_amount) = " + insert_str
        query += conflict_str
        values = values*2

        self.cur.execute(query, values)
        self.cur.connection.commit()

        logger.info(' '.join([str(i) for i in retrieved_values]))


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

    ### test ###
    # print sp.summarize_props_giving_data()
    # print sp.summarize_recharging_data()
    # print sp.summarize_compere_data()
    # print sp.summarize_auth_data()
    # print sp.summarize_data()

    # print sp.retrieve_props_giving_data()
    # print sp.retrieve_recharging_data()
    # print sp.retrieve_compere_data()
    # print sp.retrieve_auth_data()
    # print sp.retrieve_data()

    if len(sys.argv) > 1:
        if sys.argv[1] in ['summarize', 's']:
            sp.summarize()
            print "Finish"
        else:
            print "unrecognized command"
    else:
        sp.run()

    pass
