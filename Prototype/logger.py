# -*- coding: utf-8 -*-
# 
# logger.py
#
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import logging
import logging.config


def configure_logger():
  logging.config.fileConfig('logging.ini')

def logger():
  return logging.getLogger(__name__)
