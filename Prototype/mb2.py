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
            data = plistlib.dumps(msg, fmt=plistlib.FMT_BINARY)
            header_data = device_link.Header(len(data)).encode()
            #
            self._channel.write(header_data)
            self._channel.write(data)
        #
        return (yield self._read_message())

    def _validate_header(self, header):
        if header.size > self.MAX_REPLY_SIZE:
            raise RuntimeError('Lockdown header size is too big!')

    @async.coroutine
    def _read_message(self):
        header_data = yield self._channel.read_async(device_link.Header.SIZE)
        header = device_link.Header.decode(header_data)
        self._validate_header(header)
        data = yield self._channel.read_async(header.size)
        message = plistlib.loads(data, fmt=plistlib.FMT_BINARY)
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
        app_log.debug('Connecting to an mb2 service...', **log_extra(self))
        yield self._session.start()
        try:
            yield self._device_link_version_exchange()
            yield self._hello()
        except Exception as e:
            self._session.stop()
            raise e
        app_log.info('Connected to an mb2 service. Handshake is finished.', **log_extra(self))

    def close(self):
        self._session.stop()
        app_log.info('Closed', **log_extra(self))


    @async.coroutine
    def _hello(self):
        versions = [2.0, 2.1]
        app_log.debug('Sending \'hello\' message. Supported protocol versions are: {0}...'.format(versions), **log_extra(self))
        reply = yield self._device_link_process_message(create_message_hello(versions))
        #
        if 'MessageName' not in reply or reply['MessageName'] != 'Response':
            raise RuntimeError('Failed to handle \'hello\' message. Bad reply: {0}'.format(reply))
        app_log.info('Device protocol version is: {0}'.format(reply['ProtocolVersion']))
        if reply['ErrorCode'] != 0:
            raise RuntimeError('Failed to handle \'hello\' message. No common version')


    @async.coroutine
    def _device_link_version_exchange(self):
        VERSION_MAJOR = 300
        VERSION_MINOR = 0
        #
        app_log.debug('Waiting for a version exchange. Expected version is: {0}.{1}'.format(VERSION_MAJOR, VERSION_MINOR), **log_extra(self))
        reply = yield self._session.fetch()
        if len(reply) != 3 or reply[0] != 'DLMessageVersionExchange':
            raise RuntimeError('Version exchange failed. Bad reply: {0}'.format(reply))
        #
        major = reply[1]
        minor = reply[2]
        if major > VERSION_MAJOR or (major == VERSION_MAJOR and minor > VERSION_MINOR):
            raise RuntimeError('Version exchange failed. Device version is: {0}.{1}'.format(major, minor))
        else:
            app_log.info('Device version is: {0}.{1}'.format(major, minor), **log_extra(self))
        #
        reply = yield self._session.fetch(device_link.create_message_dl_version_ok(VERSION_MAJOR, VERSION_MINOR))
        if 'DLMessageDeviceReady' not in reply:
            raise RuntimeError('Version exchange failed. The expected version is not accepted.'.format(reply))
        #
        app_log.info('The expected version is accepted.', **log_extra(self))

    @async.coroutine
    def _device_link_process_message(self, message):
        reply = yield self._session.fetch(device_link.create_message_process_message(message))
        if len(reply) != 2 or reply[0] != 'DLMessageProcessMessage':
            raise RuntimeError('Failed to process message via device link. Bad reply: {0}'.format(reply))
        return reply[1]
