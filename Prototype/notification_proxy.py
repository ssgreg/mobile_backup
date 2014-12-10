# -*- coding: utf-8 -*-
# 
# notification_proxy.py
# NotificationProxy service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


#
from logger import *
from tools import *
import wl


SERVICE_TYPE = 'com.apple.mobile.notification_proxy'


#
# Service
#

class Service:
  def __init__(self, connection):
    self.connection = connection

  def close(self):
    logger().debug('Closing NotificationProxy connection...')
    self.connection.close()
