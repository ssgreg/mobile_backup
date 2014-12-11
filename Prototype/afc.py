# -*- coding: utf-8 -*-
# 
# afc.py
# AppleFileCoduit service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


import struct
#
from logger import *
from tools import *
import wl


AFC_SERVICE_TYPE = 'com.apple.afc'


#
# OpenFileWLink
#

class OpenFileWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.afc.open_file(self.data.path, self.data.mode, lambda x: self.blocked() or self.on_open_file(x))
    self.stop_next()

  def on_open_file(self, handle):
    self.data.handle = handle
    print(handle)
    self.next()


#
# Service
#

class Service:
  def __init__(self, connection):
    self.data = dict(connection=connection)
    #
    self.workflow = wl.WorkflowBatch(
      InternalChangeSessionToAfcWLink(self.data),
    )
    self.workflow.start()

  def open_file(self, path, mode, on_result):
    self.workflow = wl.WorkflowBatch(
      InternalOpenFileWLink(self.data, path=path, mode=mode),
      wl.ProxyWorkflowLink(lambda: on_result(self.data['handle']))
    )
    self.workflow.start()

  def close(self):
    logger().debug('Closing AFC connection...')
    self.data['connection'].close()


#
# InternalChangeSessionToAfcWLink
#

class InternalChangeSessionToAfcWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.session = Session(self.data.connection)
    self.next()


#
# InternalOpenFileWLink
#

class InternalOpenFileWLink(wl.WorkflowLink):
  def proceed(self):
    # mode: 2
    logger().debug('InternalOpenFileWLink: Opening file {0}'.format(self.data.path))
    self.data.session.send(13, None, None, lambda x, y: self.blocked() or self.on_open_file(x, y))
    self.stop_next()

  def on_open_file(self, data, payload):
    self.data.handle = int.from_bytes(data, byteorder='little')
    self.next()


#
# Session
#

class Session:
  def __init__(self, connection):
    self.__channel = PacketChannel(connection)
    self.__channel.on_incoming_packet = self.on_incoming_packet
    self.callbacks = {}
    self.index = 0
    logger().debug('Afc session has started.')

  def send(self, operation, data, payload, on_result):
    self.callbacks[self.index] = on_result
    self.__channel.send(operation, data, payload, self.index)
    self.index += 1

  def on_incoming_packet(self, data, payload, index):
    self.callbacks[index](data, payload)
    del self.callbacks[index]


#
# MessageReceiver
#

class MessageReceiver:
  def __init__(self):
    self.reset()

  def recv(self, connection):
    if not self.header:
      if len(self.__data) < Header.SIZE:
        self.__data += connection.recv(Header.SIZE - len(self.__data))
        if len(self.__data) == Header.SIZE:
          self.header = Header()
          self.header.decode(self.__data)
          self.__data = b''
          if self.header.size == 0 and self.header.payload_size == 0:
            return True
    elif self.header.size > 0:
      if len(self.__data) < self.header.size:
        self.__data += connection.recv(self.header.size - len(self.__data))
        if len(self.__data) == self.header.size:
          self.data = self.__data
          self.__data = b''
          if self.header.payload_size == 0:
            return True
    elif self.header.payload_size > 0:
      if len(self.__data) < self.header.size:
        self.__data += connection.recv(self.header.payload_size - len(self.__data))
        if len(self.__data) == self.header.size:
          self.payload = self.__data
          self.__data = b''
          return True
    return False

  def reset(self):
    self.header = None
    self.data = b''
    self.payload = b''
    self.__data = b''


#
# PacketChannel
#

class PacketChannel:
  def __init__(self, connection):
    self.connection = connection
    self.connection.on_ready_to_recv = self.__on_ready_to_recv
    self.on_incoming_packet = lambda data, tag, mtype: None
    self.__message_receiver = MessageReceiver()

  def send(self, operation, data, payload, index):
    header = Header(len(data) if data else 0, len(payload) if payload else 0, index, operation)
    self.connection.send(header.encode())
    # if data:
    #   self.connection.send(data)
    # if payload:
    #   self.connection.send(payload)

  def __on_ready_to_recv(self):
    if self.__message_receiver.recv(self.connection):
      header = self.__message_receiver.header
      data = self.__message_receiver.data
      payload = self.__message_receiver.payload
      self.__message_receiver.reset()
      if header.magic != header.MAGIC:
        raise RuntimeError('Incorrect packet header.')
      self.on_incoming_packet(data, payload, header.index)


#
# Header
#

class Header:
  SIZE = 40
  MAGIC = b'CFA6LPAA'

  def __init__(self, size=None, payload_size=None, index=None, operation=None):
    self.magic = self.MAGIC
    self.size = size
    self.payload_size = payload_size
    self.index = index
    self.operation = operation

  def encode(self):
    return struct.pack('<8sQQQQ', self.magic, self.size  + self.SIZE, self.size + self.SIZE + self.payload_size, self.index, self.operation)

  def decode(self, encoded):
    self.magic, self.size, self.payload_size, self.index, self.operation = struct.unpack_from('<8sQQQQ', encoded)
    self.payload_size -= self.size
    self.size -= self.SIZE

