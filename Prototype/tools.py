# -*- coding: utf-8 -*-
# 
# tools.py
#
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


def log_extra(obj):
    oid = id(obj)
    hsh = (oid & 0xffff) + ((oid & 0xffff0000) >> 16)
    return dict(
        extra=dict(
            classname=obj.__class__.__name__,
            classid=hex(hsh)
        )
    )

def log_extra_cls(cls):
    return dict(
        extra=dict(
            classname=cls.__name__,
        )
    )
