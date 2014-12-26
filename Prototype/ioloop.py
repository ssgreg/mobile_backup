# -*- coding: utf-8 -*-
# 
# ioloop.py
# ioloop
#
# Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import sched
import select
import socket
import sys
import time
#
import async
from logger import app_log
from tools import log_extra


#
# IOLoop
#

class IOLoop:
    def __init__(self):
        self._scheduler = sched.scheduler(time.time, self._process_io)
        self._ios = []
        self._cios = []
        self._hs = {}

    @staticmethod
    def instance():
        if not hasattr(IOLoop, "_instance"):
            IOLoop._instance = IOLoop()
        return IOLoop._instance

    def has_io(self):
        return len(self._ios)

    def start(self):
        while True:
            self._scheduler.run()
            if not self.has_io():
                break
            self._process_io()

    def register(self, io, read_callback, connect_callback):
        self._ios.append(io)
        self._cios.append(io)
        self._hs[io] = (read_callback, connect_callback)

    def unregister(self, io):
        self._filter_obj(self._ios, io)
        self._filter_obj(self._cios, io)
        self._hs.pop(io, None)

    def _filter_obj(self, objects, obj):
        objects[:] = [x for x in objects if x != obj]

    def _process_io(self, timeout=None):
        if self.has_io():
            rios, wios, eios = select.select(self._ios, self._cios, [], timeout)
            for io in wios:
                self._filter_obj(self._cios, io)
                self._hs[io][1]()
            for io in rios:
                self._hs[io][0]()
        else:
            time.sleep(timeout)

    @property
    def scheduler(self):
        return self._scheduler


#
# SocketChannel
#

class SocketChannel:
    def __init__(self, address, family=socket.AF_INET, type=socket.SOCK_STREAM):
        self._address = address
        self._family = family
        self._type = type
        self._future = None
        self._data = b''
        self._size = 0
        self.on_notification = lambda: None

    def connect_async(self):
        self._io = socket.socket(self._family, self._type)
        IOLoop.instance().register(self._io, self._on_data, self._on_connect)
        self._io.connect(self._address)
        self._future = async.Future()
        app_log.debug('Connecting to \'{0}\' using socket \'{1}\'...'.format(self._address, self.id), **log_extra(self))
        return self._future

    def close(self):
        app_log.debug('Closing socket \'{0}\'...'.format(self.id), **log_extra(self))
        IOLoop.instance().unregister(self._io)
        self._io.close()

    def write(self, data):
        self._io.send(data)

    def read_async(self, size):
        self._data = b''
        self._size = size
        self._future = async.Future()
        return self._future

    def _on_data(self):
        if not self._future:
            self.on_notification().add_done_callback(lambda future: future.result())
        if self._future:
            if len(self._data) < self._size:
                try:
                    read = self._io.recv(self._size - len(self._data))
                except:
                    self._future.set_exc_info(sys.exc_info())
                else:
                    if not read:
                        self._future.set_exception('SocketChannel: Connection forcibly closed.')
                    self._data += read
            if len(self._data) >= self._size:
                future = self._future
                self._future = None
                future.set_result(self._data)

    def _on_connect(self):
        if not self._future:
            raise RuntimeError('SocketChannel: Future does not set')
        self._future.set_result(True)

    @property
    def id(self):
        return self._io.fileno()
