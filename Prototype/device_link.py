# -*- coding: utf-8 -*-
# 
# device_link.py
# DeviceLink service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


def create_device_link_message_dl_version_ok(major, minor):
  return [
    'DLMessageVersionExchange',
    'DLVersionsOk',
    major
  ]

def create_device_link_message_process_message(message):
  return [
    'DLMessageProcessMessage',
    message
  ]
