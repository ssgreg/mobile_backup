# -*- coding: utf-8 -*-
# 
# lockdown.py
# Lockdown service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import plistlib
import struct
#
from logger import *
from tools import *

#
# LockdownHeader
#

class LockdownHeader:
  SIZE = 4

  def __init__(self, size=None):
    self.size = size

  def encode(self):
    return struct.pack('>I', self.size)

  def decode(self, encoded):
    self.size = struct.unpack_from('>I', encoded)[0]


def makeLockdownHeader(size=None):
  return LockdownHeader(size)


#
# LockdownMessageChannel
#

class LockdownMessageChannel:
  def __init__(self, connection):
    self.connection = connection
    self.connection.on_ready_to_recv = self.__on_ready_to_recv
    self.on_incoming_message = lambda data: None
    self.__message_receiver = MessageReceiver(makeLockdownHeader, LockdownHeader.SIZE)

  def send(self, data):
    header = LockdownHeader(len(data))
    self.connection.send(header.encode())
    self.connection.send(data)

  def __on_ready_to_recv(self):
    if self.__message_receiver.recv(self.connection):
      data = self.__message_receiver.data
      header = self.__message_receiver.header
      self.__message_receiver.reset()
      self.on_incoming_message(data)


#
# LockdownPlistChannel
#

class LockdownPlistChannel:
  def __init__(self, connection):
    self.internal_channel = LockdownMessageChannel(connection)
    self.internal_channel.on_incoming_message = self.__on_incoming_message
    self.on_incoming_plist = lambda plist_data: None

  def send(self, plist_data):
    self.internal_channel.send(plistlib.dumps(plist_data))

  def __on_incoming_message(self, data):
    plist_data = plistlib.loads(data)
    self.on_incoming_plist(plist_data)


#
# LockdownSession
#

class LockdownSession:
  FIELD_REQUEST = 'Request'

  def __init__(self, connection):
    self.__connection = connection
    self.__channel = LockdownPlistChannel(connection)
    self.__channel.on_incoming_plist = self.__on_incoming_plist
    self.reset()
    logger().debug('Lockdown session has started.')

  def send(self, plist_data, on_result):
    if self.FIELD_REQUEST not in plist_data:
      raise RuntimeError('Passed plist does not contain obligatory fields.')
    self.callback = on_result
    self.original_request = plist_data[self.FIELD_REQUEST]
    self.__channel.send(plist_data)

  def __on_incoming_plist(self, plist_data):
    if self.FIELD_REQUEST not in plist_data or plist_data[self.FIELD_REQUEST] != self.original_request:
      raise RuntimeError('Lockdown received incorrect data.')
    # store callback locally to avoid problems with calling 'send' in callback
    callback = self.callback
    self.reset()
    callback(plist_data)

  def enable_ssl(self, cert, key):
    self.__connection.enable_ssl(cert, key)

  def reset(self):
    self.callback = None
    self.original_request = ''
