# -*- coding: utf-8 -*-
#
# mb2.py
# mobile_backup2 service
#
# Created by Grigory Zubankov.
# Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import plistlib
import device_link
#
import async
from logger import app_log
from tools import log_extra


MB2_SERVICE_TYPE = 'com.apple.mobilebackup2'


def create_message_hello(versions):
  return dict(
    SupportedProtocolVersions=versions,
    MessageName='Hello'
  )


#
# InternalSession
#

class InternalSession:
    MAX_REPLY_SIZE = 1 * (1024 * 1024)  # 1 MB

    def __init__(self, channel_factory):
        self._channel_factory = channel_factory
        self._channel = None

    @async.coroutine
    def start(self):
        self._channel = yield self._channel_factory(service=MB2_SERVICE_TYPE, use_escrow_bag=True)

    def stop(self):
        self._channel.close()

    @async.coroutine
    def fetch(self, msg=None):
        if msg:
            request_data = plistlib.dumps(msg)
            self._channel.write(request_data)
        #
        return (yield self._read_message())

    def _validate_header(self, header):
        if header.size > self.MAX_REPLY_SIZE:
            raise RuntimeError('Lockdown header size is too big!')

    def _validate_message(self, msg):
        if 'Request' not in msg:
            raise RuntimeError('Message does not contain a \'Request\' field.')

    @async.coroutine
    def _read_message(self):
        # header_data = yield self._channel.read_async(LockdownHeader.SIZE)
        # header = LockdownHeader.decode(header_data)
#        self._validate_header(header)
        data = yield self._channel.read_async(header.size)
        message = plistlib.loads(data)
        self._validate_message(message)
        return message

    def enable_ssl(self, cert, key):
        self._channel.enable_ssl(cert, key)


#
# Client
#

class Client:
    def __init__(self, channel_factory):
        self._session = InternalSession(channel_factory)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    @staticmethod
    @async.coroutine
    def make(channel_factory):
        client = Client(channel_factory)
        yield client.connect()
        return client

    @async.coroutine
    def connect(self):
        app_log.debug('Connecting to a mb2 service...', **log_extra(self))
        yield self._session.start()
        try:
            yield self._device_link_version_exchange()
        except Exception as e:
            self._session.stop()
            raise e
        app_log.info('Connected to a mb2 service... Handshake is finished.', **log_extra(self))

    def close(self):
        self._session.stop()
        app_log.info('Closed', **log_extra(self))


    @async.coroutine
    def _device_link_version_exchange(self):
        VERSION_MAJOR = 300
        VERSION_MINOR = 0

        app_log.debug('Waiting for a version exchange. Expected version is: {0}.{1}'.format(VERSION_MAJOR, VERSION_MINOR), **log_extra(self))
        reply = yield self._session.fetch(device_link.create_device_link_message_dl_version_ok(VERSION_MAJOR, VERSION_MINOR))
        # #
        # if 'Error' in reply:
        #     raise RuntimeError('Failed to validate pair. Error: {0}'.format(reply['Error']))
        app_log.info('Done.', **log_extra(self))
