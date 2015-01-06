# -*- coding: utf-8 -*-
# 
# device_link.py
# DeviceLink service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import struct


def create_message_dl_version_ok(major, minor):
  return [
    'DLMessageVersionExchange',
    'DLVersionsOk',
    major
  ]

def create_message_process_message(message):
  return [
    'DLMessageProcessMessage',
    message
  ]


#
# Header
#

class Header:
    SIZE = 4

    def __init__(self, size=None):
        self.size = size

    def encode(self):
        return struct.pack('>I', self.size)

    @classmethod
    def decode(cls, encoded):
        size = struct.unpack_from('>I', encoded)[0]
        return Header(size)


