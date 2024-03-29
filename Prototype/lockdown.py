# -*- coding: utf-8 -*-
#
# lockdown.py
# Lockdown service
#
# Created by Grigory Zubankov.
# Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import plistlib
import struct
#
import about
import async
from logger import app_log
from tools import log_extra


LOCKDOWN_SERVICE_PORT = 62078
LOCKDOWN_SERVICE_TYPE = 'com.apple.mobile.lockdown'


def create_message(request):
    return dict(
        Label=about.APPLICATION_ID,
        Request=request
    )


def create_message_query_type():
    return create_message('QueryType')


def create_message_get_value(domain=None, key=None):
    msg = create_message('GetValue')
    if domain:
        msg.update(Domain=domain)
    if key:
        msg.update(Key=key)
    return msg


def create_message_validate_pair(host_id):
    msg = create_message('ValidatePair')
    msg.update(
        PairRecord=dict(HostID=host_id),
        ProtocolVersion='2'
    )
    return msg


def create_message_start_session(host_id, buid):
    msg = create_message('StartSession')
    msg.update(
        HostID=host_id,
        SystemBUID=buid
    )
    return msg


def create_message_start_service(service, escrow_bag=None):
    msg = create_message('StartService')
    msg.update(Service=service)
    if escrow_bag:
        msg.update(EscrowBag=escrow_bag)
    return msg


#
# LockdownHeader
#

class LockdownHeader:
    SIZE = 4

    def __init__(self, size=None):
        self.size = size

    def encode(self):
        return struct.pack('>I', self.size)

    @classmethod
    def decode(cls, encoded):
        size = struct.unpack_from('>I', encoded)[0]
        return LockdownHeader(size)


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
        self._channel = yield self._channel_factory(LOCKDOWN_SERVICE_PORT)

    def stop(self):
        self._channel.close()

    @async.coroutine
    def fetch(self, msg):
        request_data = plistlib.dumps(msg)
        request_header_data = LockdownHeader(len(request_data)).encode()
        #
        self._channel.write(request_header_data)
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
        header_data = yield self._channel.read_async(LockdownHeader.SIZE)
        header = LockdownHeader.decode(header_data)
        self._validate_header(header)
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
    def __init__(self, pair_record, buid, channel_factory):
        self._pair_record = pair_record
        self._buid = buid
        self._session = InternalSession(channel_factory)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    @staticmethod
    @async.coroutine
    def make(pair_record, buid, channel_factory):
        client = Client(pair_record, buid, channel_factory)
        yield client.connect()
        return client

    @async.coroutine
    def connect(self):
        app_log.debug('Connecting to a lockdown service...', **log_extra(self))
        yield self._session.start()
        try:
            yield self._query_type()
            yield self._validate_pair_record()
            yield self._start_session()
        except Exception as e:
            self._session.stop()
            raise e
        app_log.info('Connected to a lockdown service. Handshake is finished.', **log_extra(self))

    def close(self):
        self._session.stop()
        app_log.info('Closed', **log_extra(self))

    @async.coroutine
    def start_service(self, name, use_escrow_bag=False):
        app_log.debug('Starting \'{0}\' with escrow_bag={1}...'.format(name, use_escrow_bag), **log_extra(self))
        escrow_bag = self._pair_record['EscrowBag'] if use_escrow_bag else None
        reply = yield self._session.fetch(create_message_start_service(name, escrow_bag))
        #
        if 'Error' in reply:
            if reply['Error'] == 'EscrowLocked':
                raise RuntimeError('It''s impossible to get access the device because it is locked with a passcode. You must enter a passcode on the device before it can be accessed.')
            else:
                raise RuntimeError('Failed to start service. Error: {0}'.format(reply['Error']))
        port = reply['Port']
        ssl_needed = True if 'EnableServiceSSL' in reply and reply['EnableServiceSSL'] == True else False
        app_log.info('Done. Port={0}, ssl_needed={1}'.format(port, ssl_needed), **log_extra(self))
        return port, ssl_needed

    @async.coroutine
    def get_value(self, domain=None, key=None):
        app_log.debug('Getting value with domain={0} and key={1}...'.format(domain, key), **log_extra(self))
        reply = yield self._session.fetch(create_message_get_value(domain, key))
        #
        value = None
        if 'Error' in reply:
            if reply['Error'] != 'MissingValue':
                raise RuntimeError('Failed to get value. Reply: {0}'.format(reply))
        if 'Value' in reply:
            value = reply['Value']
        app_log.info('Done.', **log_extra(self))
        return value

    @async.coroutine
    def _query_type(self):
        app_log.debug('Querying lockdown type...', **log_extra(self))
        reply = yield self._session.fetch(create_message_query_type())
        #
        if 'Type' not in reply:
            raise RuntimeError('Failed to query the lockdown service type. Answer: {0}'.format(reply))
        app_log.info('Done. Type={0}'.format(reply['Type']), **log_extra(self))

    @async.coroutine
    def _validate_pair_record(self):
        app_log.debug('Validating pair record...', **log_extra(self))
        host_id = self._pair_record['HostID']
        reply = yield self._session.fetch(create_message_validate_pair(host_id))
        #
        if 'Error' in reply:
            raise RuntimeError('Failed to validate pair. Error: {0}'.format(reply['Error']))
        app_log.info('Done.', **log_extra(self))

    @async.coroutine
    def _start_session(self):
        app_log.debug('Starting the session with BUID={0}...'.format(self._buid), **log_extra(self))
        host_id = self._pair_record['HostID']
        reply = yield self._session.fetch(create_message_start_session(host_id, self._buid))
        #
        if 'Error' in reply:
            raise RuntimeError('Failed to start the session. Error: {0}'.format(reply['Error']))
        session_id = reply['SessionID']
        use_ssl = reply['EnableSessionSSL']
        if use_ssl:
            self._session.enable_ssl(self._pair_record['HostCertificate'], self._pair_record['HostPrivateKey'])
        app_log.info('Done. SessionID={0}'.format(session_id), **log_extra(self))
