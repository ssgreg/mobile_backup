# -*- coding: utf-8 -*-
# 
# tools.py
#
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import tempfile
import os
import ssl


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


def ssl_wrap_socket(io, certificate, key):
    certfile = tempfile.NamedTemporaryFile(delete=False) if certificate else None
    keyfile = tempfile.NamedTemporaryFile(delete=False) if key else None
    try:
        if certfile:
            certfile.write(certificate)
            certfile.close()
            certfile = certfile.name
        if keyfile:
            keyfile.write(key)
            keyfile.close()
            keyfile = keyfile.name
        return ssl.wrap_socket(io, certfile=certfile, keyfile=keyfile, ssl_version=3)
    finally:
        if certfile:
            os.remove(certfile)
        if keyfile:
            os.remove(keyfile)


def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)
