# -*- coding: utf-8 -*-
# 
# logger.py
#
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import logging
import logging.handlers
import sys


#
# exc_info
#

class LogFormatter(logging.Formatter):
    DEFAULT_FORMAT = '%(color)s[%(levelname)1.1s %(asctime)s %(module)s.%(classname)s%(funcName)s:%(lineno)d]%(end_color)s %(message)s'
    DEFAULT_DATE_FORMAT = '%y%m%d-%H%M%S'
    DEFAULT_ENDC = '\033[0m'
    DEFAULT_COLORS = {
        logging.DEBUG:   '\033[34m',  # Blue
        logging.INFO:    '\033[32m',  # Green
        logging.WARNING: '\033[33m',  # Yellow
        logging.ERROR:   '\033[31m',  # Red
    }

    def __init__(self, color=True):
        logging.Formatter.__init__(self, datefmt=self.DEFAULT_DATE_FORMAT)
        self._fmt = self.DEFAULT_FORMAT
        self._colors = {}
        self._normal = ''
        #
        if color:
            self._colors = self.DEFAULT_COLORS
            self._normal = self.DEFAULT_ENDC

    def format(self, record):
        # fix record values
        record.message = record.getMessage()
        record.asctime = self.formatTime(record, self.datefmt)
        if record.levelno in self._colors:
            record.color = self._colors[record.levelno]
            record.end_color = self._normal
        else:
            record.color = record.end_color = ''

        data = dict(record.__dict__)
        if not 'classname' in data:
            data['classname'] = ''
        else:
            if 'classid' in data:
                data['classname'] += '(' + data['classid'] + ')'
            data['classname'] += '.'

        # format string
        formatted = self._fmt % data
        # format exception
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            lines = [formatted.rstrip()]
            lines.extend(ln for ln in record.exc_text.split('\n'))
            formatted = '\n'.join(lines)
        # tab lines
        return formatted.replace("\n", "\n    ")


app_log = logging.getLogger('mobilebackup.application')


def enable_pretty_logging(level, logger=app_log):
    logger.setLevel(level=level)
    # file channel
    channel = logging.handlers.RotatingFileHandler(
        filename='mb.log',
        maxBytes=1 * 1024 * 1024,
        backupCount=5
    )
    channel.setFormatter(LogFormatter(color=False))
    logger.addHandler(channel)
    # console channel
    channel = logging.StreamHandler(sys.stdout)
    channel.setFormatter(LogFormatter())
    logger.addHandler(channel)
