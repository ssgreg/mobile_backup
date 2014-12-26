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


def create_message_get_value():
    return create_message('GetValue')


def create_message_validate_pair(host_id):
    msg = create_message('ValidatePair')
    msg.update(
        PairRecord=dict(HostID=host_id),
        ProtocolVersion='2'
    )


def create_message_start_session(host_id, buid):
    msg = create_message('StartSession')
    msg.update(
        HostID=host_id,
        SystemBUID=buid
    )


def create_message_start_service(service, escrow_bag=None):
    msg = create_message('StartService')
    msg.update(Service=service)
    if escrow_bag:
        msg.update(EscrowBag=escrow_bag)
    return msg


#
# Session
#

class Session:
    def __init__(self):
        pass

#
# Client
#

class Client:
    def __init__(self, channel_factory):
        self._channel_factory = channel_factory
        self._temp = None

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    @staticmethod
    @async.coroutine
    def make(channel_factory):
        client = Client(channel_factory);
        app_log.debug('Making a lockdown.Client...', **log_extra(client))
        yield client._connect()
        app_log.info('A lockdown.Client object is created', **log_extra(client))
        return client

    @async.coroutine
    def start_service(self, name):
        return 10

    @async.coroutine
    def close(self):
        self._temp.close()
#        yield self._session.stop()

    @async.coroutine
    def _connect(self):
        self._temp = yield self._channel_factory(LOCKDOWN_SERVICE_PORT)
#        yield self._session.start()
#        self._buid = yield self._read_buid()
        return self



#
# #
# # LockdownHeader
# #
#
# class LockdownHeader:
#   SIZE = 4
#
#   def __init__(self, size=None):
#     self.size = size
#
#   def encode(self):
#     return struct.pack('>I', self.size)
#
#   def decode(self, encoded):
#     self.size = struct.unpack_from('>I', encoded)[0]
#
#
# def makeLockdownHeader(size=None):
#   return LockdownHeader(size)
#
#
# #
# # LockdownMessageChannel
# #
#
# class LockdownMessageChannel:
#   def __init__(self, connection):
#     self.connection = connection
#     self.connection.on_ready_to_recv = self.__on_ready_to_recv
#     self.on_incoming_message = lambda data: None
#     self.__message_receiver = MessageReceiver(makeLockdownHeader, LockdownHeader.SIZE)
#
#   def send(self, data):
#     header = LockdownHeader(len(data))
#     self.connection.send(header.encode())
#     self.connection.send(data)
#
#   def __on_ready_to_recv(self):
#     if self.__message_receiver.recv(self.connection):
#       data = self.__message_receiver.data
#       header = self.__message_receiver.header
#       self.__message_receiver.reset()
#       self.on_incoming_message(data)
#
#
# #
# # LockdownPlistChannel
# #
#
# class LockdownPlistChannel:
#   def __init__(self, connection):
#     self.internal_channel = LockdownMessageChannel(connection)
#     self.internal_channel.on_incoming_message = self.__on_incoming_message
#     self.on_incoming_plist = lambda plist_data: None
#
#   def send(self, plist_data):
#     self.internal_channel.send(plistlib.dumps(plist_data))
#
#   def __on_incoming_message(self, data):
#     plist_data = plistlib.loads(data)
#     self.on_incoming_plist(plist_data)
#
#
# #
# # LockdownSession
# #
#
# class LockdownSession:
#   FIELD_REQUEST = 'Request'
#
#   def __init__(self, connection):
#     self.__connection = connection
#     self.__channel = LockdownPlistChannel(connection)
#     self.__channel.on_incoming_plist = self.__on_incoming_plist
#     self.reset()
#     logger().debug('Lockdown session has started.')
#
#   def send(self, plist_data, on_result):
#     if self.FIELD_REQUEST not in plist_data:
#       raise RuntimeError('Passed plist does not contain obligatory fields.')
#     self.callback = on_result
#     self.original_request = plist_data[self.FIELD_REQUEST]
#     self.__channel.send(plist_data)
#
#   def __on_incoming_plist(self, plist_data):
#     if self.FIELD_REQUEST not in plist_data or plist_data[self.FIELD_REQUEST] != self.original_request:
#       raise RuntimeError('Lockdown received incorrect data.')
#     # store callback locally to avoid problems with calling 'send' in callback
#     callback = self.callback
#     self.reset()
#     callback(plist_data)
#
#   def enable_ssl(self, cert, key):
#     self.__connection.enable_ssl(cert, key)
#
#   def reset(self):
#     self.callback = None
#     self.original_request = ''
#
#
# #
# # InternalConnectToServiceWLink
# #
#
# class InternalConnectToServiceWLink(wl.WorkflowLink):
#   def proceed(self):
#     self.data.connect_to_service(self.data.port, lambda x: self.blocked() or self.on_connect_to_service(x))
#     self.stop_next()
#
#   def on_connect_to_service(self, connection):
#     self.data.connection = connection
#     self.next()
#
#
# #
# # InternalChangeSessionToLockdownWLink
# #
#
# class InternalChangeSessionToLockdownWLink(wl.WorkflowLink):
#   def proceed(self):
#     self.data.session = LockdownSession(self.data.connection)
#     self.next()
#
#
# #
# # InternalQueryTypeWLink
# #
#
# class InternalQueryTypeWLink(wl.WorkflowLink):
#   def proceed(self):
#     logger().debug('InternalQueryTypeWLink: Quering lockdown service type...')
#     self.data.session.send(create_lockdown_message_query_type(), lambda x: self.blocked() or self.on_query_lockdown_type(x))
#     self.stop_next()
#
#   def on_query_lockdown_type(self, result):
#     if 'Type' in result and result['Type'] == LOCKDOWN_SERVICE_TYPE:
#       logger().debug('InternalQueryTypeWLink: Verifyed. Service type is: {0}'.format(result['Type']))
#       self.next();
#     else:
#       raise RuntimeError('Failed to query the lockdown service type. Answer: {0}'.format(result))
#
#
# #
# # InternalValidatePairRecordWLink
# #
#
# class InternalValidatePairRecordWLink(wl.WorkflowLink):
#   def proceed(self):
#     hostID = self.data.pair_record_data['HostID']
#     #
#     logger().debug('InternalValidatePairRecordWLink: Validating pair record with HostID = {0}'.format(hostID))
#     self.data.session.send(create_lockdown_message_validate_pair(hostID), lambda x: self.blocked() or self.on_validate_pair_record(x))
#     self.stop_next()
#
#   def on_validate_pair_record(self, result):
#     if 'Error' not in result:
#       logger().debug('InternalValidatePairRecordWLink: Done.')
#       self.next();
#     else:
#       raise RuntimeError('Failed to validate pair. Error: {0}'.format(result['Error']))
#
#
# #
# # InternalStartSessionWLink
# #
#
# class InternalStartSessionWLink(wl.WorkflowLink):
#   def proceed(self):
#     hostID = self.data.pair_record_data['HostID']
#     buid = self.data.buid
#     #
#     logger().debug('InternalStartSessionWLink: Starting lockdown session with HostID = {0} and BUID = {1}'.format(hostID, buid))
#     self.data.session.send(create_lockdown_message_start_session(hostID, buid), lambda x: self.blocked() or self.on_start_session(x))
#     self.stop_next()
#
#   def on_start_session(self, result):
#     if 'Error' not in result:
#       session_id = result['SessionID']
#       use_ssl = result['EnableSessionSSL']
#       logger().debug('InternalStartSessionWLink: Done. SessionID = {0}, UseSSL = {1}'.format(session_id, use_ssl))
#       if use_ssl:
#         self.data.session.enable_ssl(self.data.pair_record_data['HostCertificate'], self.data.pair_record_data['HostPrivateKey'])
#       self.next();
#     else:
#       raise RuntimeError('Failed to start session. Error: {0}'.format(result['Error']))
#
#
# #
# # InternalStartServiceWLink
# #
#
# class InternalStartServiceWLink(wl.WorkflowLink):
#   def proceed(self):
#     escrow_bag = self.data.pair_record_data['EscrowBag'] if self.data.use_escrow_bag else None
#     service_type = self.data.service_type
#     #
#     logger().debug('InternalStartServiceWLink: Starting {0} via Lockdown {1} escrow bag'.format(service_type, "with" if escrow_bag else "without"))
#     self.data.session.send(create_lockdown_message_start_service(service_type, escrow_bag), lambda x: self.blocked() or self.on_start_service(x))
#     self.stop_next()
#
#   def on_start_service(self, result):
#     if 'Error' not in result:
#       logger().debug('InternalStartServiceWLink: Done. Port = {0}'.format(result['Port']))
#       self.data.port = result['Port']
#       self.next();
#     else:
#       if result['Error'] == 'EscrowLocked':
#         raise RuntimeError('It''s impossible to get access the device because it is locked with a passcode. You must enter a passcode on the device before it can be accessed.')
#       else:
#         raise RuntimeError('Failed to start service. Error: {0}'.format(result['Error']))
#
#
# #
# # InternalGetValueWLink
# #
#
# class InternalGetValueWLink(wl.WorkflowLink):
#   def proceed(self):
#     logger().debug('InternalGetValueWLink: Getting value')
#     self.data.session.send(create_lockdown_message_get_value(), lambda x: self.blocked() or self.on_get_value(x))
#     self.stop_next()
#
#   def on_get_value(self, result):
#     if 'Value' in result:
#       logger().debug('InternalGetValueWLink: Done')
#       self.data.get_value_result = result['Value']
#       self.next();
#     else:
#       raise RuntimeError('Failed to get value. Answer is: {0}'.format(result))
#
#
# # connection = connect_to_service(port)
# # session = LockdownSession(connection)
# # self.query_type()
# # self.validate_pair_record()
# # self.start_session()
#
# #
# # LockdownService
# #
#
# class LockdownService:
#   def __init__(self, connect_to_service, pair_record, buid, on_result):
#     logger().debug('LockdownService: Connecting to lockdown service...')
#     self.data = dict(connect_to_service=connect_to_service, pair_record_data=pair_record, buid=buid)
#     self.workflow = wl.WorkflowBatch(
#       InternalConnectToServiceWLink(self.data, port=LOCKDOWN_SERVICE_PORT),
#       InternalChangeSessionToLockdownWLink(self.data),
#       InternalQueryTypeWLink(self.data),
#       InternalValidatePairRecordWLink(self.data),
#       InternalStartSessionWLink(self.data),
#       wl.ProxyWorkflowLink(on_result)
#     )
#     self.workflow.start()
#
#   def query_type(self, on_result):
#     self.workflow = wl.WorkflowBatch(
#       InternalQueryTypeWLink(self.data),
#       wl.ProxyWorkflowLink(on_result)
#     )
#     self.workflow.start()
#
#   def start_service(self, type, use_escrow_bag, on_result):
#     data = dict(self.data)
#     self.workflow = wl.WorkflowBatch(
#       InternalStartServiceWLink(data, service_type=type, use_escrow_bag=use_escrow_bag),
#       InternalConnectToServiceWLink(data),
#       wl.ProxyWorkflowLink(lambda: on_result(data['connection']))
#     )
#     self.workflow.start()
#
#   def get_value(self, on_result):
#     self.workflow = wl.WorkflowBatch(
#       InternalGetValueWLink(self.data),
#       wl.ProxyWorkflowLink(lambda: on_result(self.data['get_value_result']))
#     )
#     self.workflow.start()
#
#   def close(self):
#     logger().debug('Closing lockdown connection...')
#     if 'connection' in self.data:
#       self.data['connection'].close()
#
#
# #
# # LockdownMakeServiceWLink
# #
#
# class LockdownMakeServiceWLink(wl.WorkflowLink):
#   def proceed(self):
#     self.data.lockdown = LockdownService(self.data.connect_to_service, self.data.pair_record_data, self.data.buid, lambda: self.blocked() or self.next())
#     self.stop_next()
#
#
# #
# # LockdownQueryTypeWLink
# #
#
# class LockdownQueryTypeWLink(wl.WorkflowLink):
#   def proceed(self):
#     self.data.lockdown.query_type(lambda: self.blocked() or self.next())
#     self.stop_next()
#
#
# #
# # LockdownGetValueWLink
# #
#
# class LockdownGetValueWLink(wl.WorkflowLink):
#   def proceed(self):
#     self.data.lockdown.get_value(lambda x: self.blocked() or self.on_get_value(x))
#     self.stop_next()
#
#   def on_get_value(self, result):
#     print(str(result).encode('utf-8'))
#     self.data.get_value_result = result
#     self.next()
#
#
# #
# # LockdownStartServiceWLink
# #
#
# class LockdownStartServiceWLink(wl.WorkflowLink):
#   def proceed(self):
#     self.data.lockdown.start_service(self.data.service_type, self.data.use_escrow_bag, lambda x: self.blocked() or self.on_start_service(x))
#     self.stop_next()
#
#   def on_start_service(self, connection):
#     self.data.service_connection = connection
#     self.next()
