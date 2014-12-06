# -*- coding: utf-8 -*-
# 
# io.py
# UsbMux service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import collections
import os
import sched
import select
import ssl
import tempfile
import time
#
from logger import *


#
# IOService
#

class IOService:
  def __init__(self):
    XHolder = collections.namedtuple('XHolder', 'ios, x')
    self.scheduler = sched.scheduler(time.time, self.__process_io)
    self.__rxh = XHolder([], {})
    self.__txh = XHolder([], {})
    self.__xxh = XHolder([], {})

  def register(self, io, rx, tx=None, xx=None):
    for xh, x in ((self.__rxh, rx), (self.__txh, tx), (self.__xxh, xx)):
      if x:
        xh.ios.append(io)
        xh.x[io] = x

  def unregister(self, io):
    for xh in (self.__rxh, self.__txh, self.__xxh):
      xh.ios[:] = [x for x in xh.ios if x != io]
      xh.x.pop(io, None)

  def run(self):
    while True:
      self.scheduler.run()
      if self.has_io():
        self.__process_io()
      else:
        break

  def stopped(self):
    return self.stop_flag

  def has_io(self):
    return len(self.__rxh.ios) != 0

  def __process_io(self, timeout=None):
    if self.has_io():
      rios, tios, xios = select.select(self.__rxh.ios, self.__txh.ios, self.__xxh.ios, timeout)
      for xh, signaled_ios in ((self.__rxh, rios), (self.__txh, tios), (self.__xxh, xios)):
        for io in signaled_ios:
          xh.x[io]()
    else:
      time.sleep(timeout)


class SafeIOService:
  def __init__(self, io_service, on_exception):
    super().__init__()
    self.io_service = io_service
    self.on_exception = on_exception

  def register(self, io, rx):
    self.io_service.register(io, lambda: self.io_wrapper(rx))

  def unregister(self, io):
    self.io_service.unregister(io)

  def execute(self, action):
    self.io_wrapper(action)

  def io_wrapper(self, x):
    try:
      x()
    except(Exception) as e:
      self.on_exception(e)


#
# Connection
#

class Connection:
  def __init__(self, service, io):
    self.__io = io
    self.__service = service
    self.__service.register(io, self.__on_ready_to_recv)
    self.on_ready_to_recv = lambda: None

  def close(self):
    self.__service.unregister(self.__io)
    self.__io.close()

  def send(self, data):
    self.__io.send(data)

  def recv(self, size):
    data = self.__io.recv(size)
    if not data:
      raise RuntimeError('Connection forcibly closed.')
    return data

  def enable_ssl(self, cert=None, key=None):
    logger().debug('SSL has been enabled.')
    cert_file = tempfile.NamedTemporaryFile(delete=False) if cert else None
    key_file = tempfile.NamedTemporaryFile(delete=False) if key else None
    try:
      if cert:
        cert_file.write(cert)
        cert_file.close()
        cert_file = cert_file.name
      if key:
        key_file.write(key)
        key_file.close()
        key_file = key_file.name
      self.__service.unregister(self.__io)
      self.__io = ssl.wrap_socket(self.__io, certfile=cert_file, keyfile=key_file, ssl_version=3)
      self.__service.register(self.__io, self.__on_ready_to_recv)
    finally:
      if cert:
        os.remove(cert_file)
      if key:
        os.remove(key_file)

  def __on_ready_to_recv(self):
    self.on_ready_to_recv()
