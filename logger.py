#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import os
import gzip
import logging
from logging import handlers

from config import VERBOSE_DATA, MAX_SIZE

class CompressingFileHandler(handlers.RotatingFileHandler):
    """
    Handler for logging to a file, which has same rollover condition with RotatingFileHandler,
    but will compress the old log file instead.

    Rollover occurs whenever the current log file is nearly maxBytes in length, as like how
    RotatingFileHandler does. Parameter 'backupCount' will take no effect on this handler.
    The current log file will be compress to .gz file using gzip module, adding current date
    to file name in the format: Testing.log-20160101.gz. If a file with such file name already
    exists, a counting lable will be appended, e.g. Testing.log-20160101-01.gz,
    Testing.log-20160101-02.gz, etc.
    """

    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None, delay=0):
        super(CompressingFileHandler, self).__init__(filename, mode, maxBytes, backupCount, encoding, delay)

    def doRollover(self):
        """
        Do a rollover.
        """
        if self.stream:
            self.stream.close()
            self.stream = None

        today = datetime.datetime.today().strftime('%Y%m%d')
        sfn = '-'.join([self.baseFilename, today])
        if os.path.exists(sfn + '.gz'):
            i = 1
            while 1:
                _sfn = "%s-%d" % (sfn, i)
                if os.path.exists(_sfn + '.gz'):
                    i += 1
                else:
                    sfn = _sfn
                    break

        with open(self.baseFilename) as log, gzip.open(sfn + '.gz', 'wb') as compressed_log:
            compressed_log.writelines(log)

        os.remove(self.baseFilename)

        if not self.delay:
            self.stream = self._open()


formatter = logging.Formatter(
    fmt='%(asctime)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

handler = CompressingFileHandler(filename=VERBOSE_DATA, maxBytes=MAX_SIZE)
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)

logger = logging.getLogger("StatProcessor")
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)


if __name__ == '__main__':
    pass
