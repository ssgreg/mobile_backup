# -*- coding: utf-8 -*-
# 
# mobilebackup2.py
# MobileBackup2 service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


def create_mobilebackup2_message_hello(versions):
  return dict(
    SupportedProtocolVersions=versions,
    MessageName='Hello'
  )
