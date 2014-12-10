# -*- coding: utf-8 -*-
# 
# afc.py
# AppleFileCoduit service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


#
from logger import *
from tools import *
import wl


AFC_SERVICE_TYPE = 'com.apple.afc'


#
# Service
#

class Service:
  def __init__(self, connection):
    self.connection = connection

  def close(self):
    logger().debug('Closing AFC connection...')
    self.connection.close()
