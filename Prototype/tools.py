# -*- coding: utf-8 -*-
# 
# tools.py
#
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


#
# MessageReceiver
#

class MessageReceiver:
  def __init__(self, header_factory=None, header_size=None):
    self.__header_factory = header_factory
    self.__header_size = header_size
    self.reset()

  def recv(self, connection):
    if not self.header:
      if len(self.data) < self.__header_size:
        self.data += connection.recv(self.__header_size - len(self.data))
        if len(self.data) == self.__header_size:
          self.header = self.__header_factory()
          self.header.decode(self.data)
          self.data = b''
    if self.header:
      if len(self.data) < self.header.size:
        self.data += connection.recv(self.header.size - len(self.data))
        if len(self.data) == self.header.size:
          return True
    return False

  def reset(self):
    self.header = None
    self.data = b''
