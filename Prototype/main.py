# -*- coding: utf-8 -*-
# 
# main.py
# start point
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import argparse
import plistlib
import socket
import struct
import sys
#
from io_service import *
from logger import *
from tools import *
import usbmux
import wl


#
# PlistHeader
#

class PlistHeader:
  SIZE = 4

  def __init__(self, size=None):
    self.size = size

  def encode(self):
    return struct.pack('>I', self.size)

  def decode(self, encoded):
    self.size = struct.unpack_from('>I', encoded)[0]


def makePlistHeader(size=None):
  return PlistHeader(size)


#
# PlistMessageChannel
#

class PlistMessageChannel:
  def __init__(self, connection):
    self.connection = connection
    self.connection.on_ready_to_recv = self.__on_ready_to_recv
    self.on_incoming_message = lambda data: None
    self.__message_receiver = MessageReceiver(makePlistHeader, PlistHeader.SIZE)

  def send(self, data):
    header = PlistHeader(len(data))
    self.connection.send(header.encode())
    self.connection.send(data)

  def __on_ready_to_recv(self):
    if self.__message_receiver.recv(self.connection):
      data = self.__message_receiver.data
      header = self.__message_receiver.header
      self.__message_receiver.reset()
      self.on_incoming_message(data)


#
# PlistChannel
#

class PlistChannel:
  def __init__(self, connection):
    self.internal_channel = PlistMessageChannel(connection)
    self.internal_channel.on_incoming_message = self.__on_incoming_message
    self.on_incoming_plist = lambda plist_data: None

  def send(self, plist_data):
    self.internal_channel.send(plistlib.dumps(plist_data))

  def __on_incoming_message(self, data):
    plist_data = plistlib.loads(data)
    self.on_incoming_plist(plist_data)


#
# LockdownSession
#

class LockdownSession:
  FIELD_REQUEST = 'Request'

  def __init__(self, connection):
    self.__connection = connection
    self.__channel = PlistChannel(connection)
    self.__channel.on_incoming_plist = self.__on_incoming_plist
    self.reset()
    logger().debug('Lockdown session has started.')

  def send(self, plist_data, on_result):
    if self.FIELD_REQUEST not in plist_data:
      raise RuntimeError('Passed plist does not contain obligatory fields.')
    self.callback = on_result
    self.original_request = plist_data[self.FIELD_REQUEST]
    self.__channel.send(plist_data)

  def __on_incoming_plist(self, plist_data):
    if self.FIELD_REQUEST not in plist_data or plist_data[self.FIELD_REQUEST] != self.original_request:
      raise RuntimeError('Lockdown received incorrect data.')
    # store callback locally to avoid problems with calling 'send' in callback
    callback = self.callback
    self.reset()
    callback(plist_data)

  def enable_ssl(self, cert, key):
    self.__connection.enable_ssl(cert, key)

  def reset(self):
    self.callback = None
    self.original_request = ''



#
# CommonServiceSession
#

class CommonServiceSession:
  def __init__(self, connection):
    self.__channel = PlistChannel(connection)
    self.__channel.on_incoming_plist = self.__on_incoming_plist
    self.on_notification = lambda plist_data: None
    self.reset()
    logger().debug('Common service session has started')

  def send(self, plist_data, on_result):
    self.callback = on_result
    self.__channel.send(plist_data)

  def __on_incoming_plist(self, plist_data):
    callback = self.callback
    self.reset()
    if callback:
      callback(plist_data)
    else:
      self.on_notification(plist_data)

  def enable_ssl(self, cert, key):
    self.__connection.enable_ssl(cert, key)

  def reset(self):
    self.callback = None



def connect():
  if (sys.platform == 'darwin'):
    logger().info('Using UNIX socket to connect to the usbmuxd.')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(r'/var/run/usbmuxd')
  else:
    logger().info('Connecting to the apple service...')
    sock = socket.socket()
    sock.connect(('127.0.0.1', 27015))
  return sock

def create_lockdown_message_query_type():
  return dict(Request = 'QueryType')

def create_lockdown_message_validate_pair(host_id):
  return dict(
    Label='test',
    PairRecord = dict(HostID = host_id),
    Request = 'ValidatePair',
    ProtocolVersion = '2')

def create_lockdown_message_start_session(host_id, buid):
  return dict(
    Label='test',
    Request='StartSession',
    HostID=host_id,
    SystemBUID=buid)

def create_lockdown_message_start_service(service, escrow_bag=None):
  result = dict(
    Label='test',
    Request='StartService',
    Service=service)
  if escrow_bag:
    result['EscrowBag'] = escrow_bag
  return result

def create_device_link_message_dl_version_ok(major, minor):
  return [
    'DLMessageVersionExchange',
    'DLVersionsOk',
    major
  ]

def create_device_link_message_process_message(message):
  return [
    'DLMessageProcessMessage',
    message
  ]

def create_mobilebackup2_message_hello(versions):
  return dict(
    SupportedProtocolVersions=versions,
    MessageName='Hello'
  )

def print_device_info(device):
  print('\t'
    , 'did:', device['DeviceID']
    , '| sn:', device['Properties']['SerialNumber']
    , '| contype:', device['Properties']['ConnectionType']
    , '| pid: {0}'.format(device['Properties']['ProductID']) if 'ProductID' in device['Properties'] else '')


#
# TestGetDeviceList
#

class TestGetDeviceList:
  def __init__(self, io_service):
    self.io_service = io_service

  def start(self):
    self.connection = Connection(self.io_service, connect())
    self.internal_session = usbmux.UsbMuxSession(self.connection)
    logger().debug('Getting device list...')
    self.internal_session.send(usbmux.create_usbmux_message_list_devices(), self.on_devices)

  def on_devices(self, devices):
    print('device list:')
    for i in devices['DeviceList']:
      print_device_info(i)
    self.close()

  def close(self):
    self.connection.close()


#
# TestListenForDevices
#

class TestListenForDevices:
  def __init__(self, io_service, timeout):
    self.io_service = io_service
    self.timeout = timeout

  def start(self):
    self.connection = Connection(self.io_service, connect())
    self.internal_session = usbmux.UsbMuxSession(self.connection)
    self.internal_session.on_notification = self.on_notification
    #
    logger().debug('Listening for devices...')
    self.internal_session.send(usbmux.create_usbmux_message_listen(), self.on_listen)


  def on_listen(self, confirmation):
    logger().debug('Listen confirmed')
    self.io_service.scheduler.enter(self.timeout, 1, self.close, ())

  def on_notification(self, notification):
    if notification['MessageType'] == 'Attached':
      print('Device attached:')
      print_device_info(notification)
      sys.stdout.flush()
    else:
      print('Device dettached:')
      print('\t', 'did:', notification['DeviceID'])
      sys.stdout.flush()

  def close(self):
    self.connection.close()


#
# ConnectToUsbMuxdWLink
#

class ConnectToUsbMuxdWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.connection = Connection(self.data.io_service, connect())
    self.next()


#
# ListDevicesWLink
#

class ListDevicesWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('ListDevicesWLink: Getting device list...')
    self.data.session.send(usbmux.create_usbmux_message_list_devices(), lambda x: self.blocked() or self.on_list_devices(x))
    self.stop_next()

  def on_list_devices(self, result):
    if 'DeviceList' in result:
      self.data.devices = result['DeviceList']
      logger().debug('ListDevicesWLink: Done. Count = {0}'.format(len(self.data.devices)))
      self.next();
    else:
      raise RuntimeError('Failed to list devices')


#
# ReadBuidWLink
#

class ReadBuidWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Reading BUID')
    self.data.session.send(usbmux.create_usbmux_message_read_buid(), lambda x: self.blocked() or self.on_read_buid(x))
    self.stop_next()

  def on_read_buid(self, result):
    if 'BUID' in result:
      self.data.buid = result['BUID']
      logger().debug('Done. BUID = {0}'.format(self.data.buid))
      self.next();
    else:
      raise RuntimeError('Failed to read BUID')


#
# ReadPairRecordWLink
#

class ReadPairRecordWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Reading pair record of a device with a sn = {0}'.format(self.data.sn))
    self.data.session.send(usbmux.create_usbmux_message_read_pair_record(self.data.sn), lambda x: self.blocked() or self.on_get_pair_record(x))
    self.stop_next()

  def on_get_pair_record(self, result):
    if 'PairRecordData' in result:
      self.data.pair_record_data = plistlib.loads(result['PairRecordData'])
      logger().debug('Done. HostID = {0}'.format(self.data.pair_record_data['HostID']))
      self.next();
    else:
      raise RuntimeError('Failed to read pair record')


#
# ConnectToServiceWLink
#

class ConnectToServiceWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Connecting to a service, did = {0} port = {1}'.format(self.data.did, self.data.service_port))
    self.data.session.send(usbmux.create_usbmux_message_connect(self.data.did, self.data.service_port), lambda x: self.blocked() or self.on_connect(x))
    self.stop_next()

  def on_connect(self, confirmation):
    if confirmation['Number'] == 0:
      logger().debug('Done')
      self.next();
    else:
      raise RuntimeError('Failed to connect with an error = {0}'.format(confirmation['Number']))


#
# SessionChangeToLockdown
#

class SessionChangeToLockdown(wl.WorkflowLink):
  def proceed(self):
    self.data.session = LockdownSession(self.data.connection)
    self.next()


#
# SessionChangeToUsbMuxWLink
#

class SessionChangeToUsbMuxWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.session = usbmux.UsbMuxSession(self.data.connection)
    self.next()


#
# SessionChangeToCommonService
#

class SessionChangeToCommonService(wl.WorkflowLink):
  def proceed(self):
    self.data.session = CommonServiceSession(self.data.connection)
    self.next()


#
# LockdownServiceCheckTypeWLink
#

class LockdownServiceCheckTypeWLink(wl.WorkflowLink):
  LOCKDOWN_SERVICE_TYPE = 'com.apple.mobile.lockdown'

  def proceed(self):
    logger().debug('Checking lockdown service type...')
    self.data.session.send(create_lockdown_message_query_type(), lambda x: self.blocked() or self.on_check_lockdown_type(x))
    self.stop_next()

  def on_check_lockdown_type(self, result):
    if 'Type' in result and result['Type'] == self.LOCKDOWN_SERVICE_TYPE:
      logger().debug('Done. Service type is: {0}'.format(result['Type']))
      self.next();
    else:
      raise RuntimeError('Failed to query the lockdown service type. Answer: {0}'.format(result))


#
# LockdownValidatePairRecordWLink
#

class LockdownValidatePairRecordWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Validating pair record with HostID = {0}'.format(self.data.pair_record_data['HostID']))
    self.data.session.send(create_lockdown_message_validate_pair(self.data.pair_record_data['HostID']), lambda x: self.blocked() or self.on_validate_pair_record(x))
    self.stop_next()

  def on_validate_pair_record(self, result):
    if 'Error' not in result:
      logger().debug('Done.')
      self.next();
    else:
      raise RuntimeError('Failed to validate pair. Error: {0}'.format(result['Error']))


#
# LockdownStartSessionWLink
#

class LockdownStartSessionWLink(wl.WorkflowLink):
  def proceed(self):
    hostID = self.data.pair_record_data['HostID']
    buid = self.data.buid
    #
    logger().debug('Starting lockdown session with HostID = {0} and BUID = {1}'.format(hostID, buid))
    self.data.session.send(create_lockdown_message_start_session(hostID, buid), lambda x: self.blocked() or self.on_start_session(x))
    self.stop_next()

  def on_start_session(self, result):
    if 'Error' not in result:
      session_id = result['SessionID']
      use_ssl = result['EnableSessionSSL']
      logger().debug('Done. SessionID = {0}, UseSSL = {1}'.format(session_id, use_ssl))
      if use_ssl:
        self.data.session.enable_ssl(self.data.pair_record_data['HostCertificate'], self.data.pair_record_data['HostPrivateKey'])
      self.next();
    else:
      raise RuntimeError('Failed to start session. Error: {0}'.format(result['Error']))


#
# LockdownStartServiceWLink
#

class LockdownStartServiceWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Starting {0} via Lockdown {1} escrow bag'.format(self.data.service_name, "with" if self.data.use_escrow_bag else "without"))
    escrow_bag = self.data.pair_record_data['EscrowBag'] if self.data.use_escrow_bag else None
    self.data.session.send(create_lockdown_message_start_service(self.data.service_name, escrow_bag), lambda x: self.blocked() or self.on_start_service(x))
    self.stop_next()

  def on_start_service(self, result):
    if 'Error' not in result:
      logger().debug('Done. Port = {0}'.format(result['Port']))
      self.data.port = result['Port']
      self.next();
    else:
      if result['Error'] == 'EscrowLocked':
        raise RuntimeError('It''s impossible to back up the device because it is locked with a passcode. You must enter a passcode on the device before it can be backed up.')
      else:
        raise RuntimeError('Failed to start service. Error: {0}'.format(result['Error']))


#
# LockdownInternalFixIds
#

class LockdownInternalFixIds(wl.WorkflowLink):
  def proceed(self):
    # sn only
    if self.data.sn and not self.data.did:
      for device in self.data.devices:
        if device['Properties']['SerialNumber'] == self.data.sn and device['Properties']['ConnectionType'] == 'USB':
          self.data.did = device['DeviceID']
          logger().debug('LockdownInternalFixIds: Fixed did = {0}'.format(self.data.did))
          break
    # did only
    elif self.data.did and not self.data.sn:
      for device in self.data.devices:
        if device['DeviceID'] == self.data.did and device['Properties']['ConnectionType'] == 'USB':
          self.data.sn = device['Properties']['SerialNumber']
          logger().debug('LockdownInternalFixIds: Fixed sn = {0}'.format(self.data.sn))
          break
    # both
    if self.data.sn and self.data.did:
      self.next()
    else:
      raise RuntimeError('LockdownInternalFixIds: There is no device with sn={0} and did={1}'.format(self.data.sn, self.data.did))


#
# LockdownInternalSaveIds
#

class LockdownInternalSaveIds(wl.WorkflowLink):
  def proceed(self):
    self.data.lockdown.did = self.data.did
    self.data.lockdown.sn = self.data.sn
    self.next()


#
# LockdownService
#

class LockdownService:
  LOCKDOWN_SERVICE_PORT = 62078

  def __init__(self, io_service):
    self.io_service = io_service
    self.connection = None
    self.data = dict(io_service=self.io_service, lockdown=self)
    self.did = None
    self.sn = None

  def connect(self, did, sn, on_result):
    logger().debug('Connecting to lockdown with did = {0} and sn = {1}'.format(did, sn))
    self.data.update(did=did, sn=sn)
    #
    workflow = wl.WorkflowBatch(
      ConnectToUsbMuxdWLink(self.data),
      SessionChangeToUsbMuxWLink(self.data),
      ListDevicesWLink(self.data),
      LockdownInternalFixIds(self.data),
      ReadBuidWLink(self.data),
      ReadPairRecordWLink(self.data),
      ConnectToServiceWLink(self.data, service_port=self.LOCKDOWN_SERVICE_PORT),
      SessionChangeToLockdown(self.data),
      LockdownServiceCheckTypeWLink(self.data),
      LockdownValidatePairRecordWLink(self.data),
      LockdownStartSessionWLink(self.data),
      LockdownInternalSaveIds(self.data),
      wl.ProxyWorkflowLink(on_result))
    workflow.start()

  def start_another_service(self, name, on_result):
    self.__start_another_service(name, False, on_result)

  def start_another_service_with_escrow_bag(self, name, on_result):
    self.__start_another_service(name, True, on_result)

  def __start_another_service(self, name, use_escrow_bag, on_result):
    workflow = wl.WorkflowBatch(
      LockdownStartServiceWLink(self.data, service_name=name, use_escrow_bag=use_escrow_bag),
      wl.ProxyWorkflowLink(lambda: self.__call_on_result_for_start_another_service(on_result, self.data)))
    workflow.start()

  def __call_on_result_for_start_another_service(self, on_result, data):
    if 'port' in data:
      on_result(data['port'])
    else:
      on_result(None)

  def close(self):
    if 'connection' in self.data:
      logger().debug('Closing lockdown connection...')
      self.data['connection'].close()
      self.data['connection'] = None


#
# UxbMuxConnectToLockdownWLink
#

class UxbMuxConnectToLockdownWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.lockdown.connect(self.data.did, self.data.sn, lambda: self.blocked() or self.on_connect_to_lockdown())
    self.stop_next()

  def on_connect_to_lockdown(self):
    self.data.did = self.data.lockdown.did
    self.data.sn = self.data.lockdown.sn
    self.next()


#
# StartServiceViaLockdown
#

class LockdownStartAnotherServiceWLink(wl.WorkflowLink):
  def proceed(self):
    if self.data.use_escrow_bag:
      fn = self.data.lockdown.start_another_service_with_escrow_bag
    else:
      fn = self.data.lockdown.start_another_service
    fn(self.data.service, lambda x: self.blocked() or self.on_start(x))
    self.stop_next()

  def on_start(self, port):
    if port:
      self.data.service_port = port
      self.next()
    else:
      raise RuntimeError('Lockdown failed to start {0}'.format(self.data.service))


#
# DeviceLinkVersionExchangeWLink
#

class DeviceLinkVersionExchangeWLink(wl.WorkflowLink):
  VERSION_MAJOR = 300
  VERSION_MINOR = 0

  def proceed(self):
    logger().debug('Waiting for version exchange. Expected version is: {0}.{1}'.format(self.VERSION_MAJOR, self.VERSION_MINOR))
    self.data.session.on_notification = lambda x: self.blocked() or self.on_handshake(x)
    self.stop_next()

  def on_handshake(self, query):
    self.data.session.on_notification = None
    if 'DLMessageVersionExchange' in query and len(query) == 3:
      major = query[1]
      minor = query[2]
      if major > self.VERSION_MAJOR or (major > self.VERSION_MAJOR and minor > self.VERSION_MINOR):
        raise RuntimeError('Version exchange failed. Device version is: {0}.{1}'.format(major, minor))
      else:
        logger().debug('Device version is: {0}.{1}'.format(major, minor))
        self.data.session.send(create_device_link_message_dl_version_ok(major, minor), lambda x: self.blocked() or self.on_version_exchange(x))
        self.stop_next()
    else:
      raise RuntimeError('Version exchange failed.')

  def on_version_exchange(self, result):
    if 'DLMessageDeviceReady' in result:
      logger().debug('Done')
      self.next()
    else:
      raise RuntimeError('Version exchange failed.')


#
# DeviceLinkInternalProcessMessageWLink
#

class DeviceLinkInternalProcessMessageWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('DeviceLinkInternalProcessMessageWLink: Processing message...')
    self.data.session.send(create_device_link_message_process_message(self.data.message), lambda x: self.blocked() or self.on_process_message(x))
    self.stop_next()

  def on_process_message(self, result):
    if result[0] == 'DLMessageProcessMessage' and len(result) == 2:
      logger().debug('DeviceLinkInternalProcessMessageWLink: Done')
      self.data.process_result = result[1]
      self.next()
    else:
      raise RuntimeError('DeviceLinkInternalProcessMessageWLink: Incorrect reply')


#
# DeviceLinkService
#

class DeviceLinkService:
  def __init__(self, io_service):
    self.io_service = io_service
    self.data = dict(io_service=self.io_service, device_link=self)

  def connect(self, did, port, on_result):
    self.workflow = wl.WorkflowBatch(
      ConnectToUsbMuxdWLink(self.data),
      SessionChangeToUsbMuxWLink(self.data),
      ConnectToServiceWLink(self.data, did=did, service_port=port),
      SessionChangeToCommonService(self.data),
      wl.ProxyWorkflowLink(on_result))
    self.workflow.start()

  def vesion_exchange(self, on_result):
    self.workflow = wl.WorkflowBatch(DeviceLinkVersionExchangeWLink(self.data), wl.ProxyWorkflowLink(on_result))
    self.workflow.start()

  def process_message(self, message, on_result):
    self.workflow = wl.WorkflowBatch(DeviceLinkInternalProcessMessageWLink(self.data, message=message), wl.ProxyWorkflowLink(on_result))
    self.workflow.start()

  def close(self):
    if 'connection' in self.data:
      logger().debug('Closing device link connection...')
      self.data['connection'].close()


#
# MobileBackup2InternalHelloWLink
#

class MobileBackup2InternalHelloWLink(wl.WorkflowLink):
  def proceed(self):
    versions = [2.0, 2.1]
    logger().debug('MobileBackup2InternalHelloWLink: Sending Hello message. Supported protocol version are: {0}...'.format(versions))
    self.data.device_link.process_message(create_mobilebackup2_message_hello(versions), lambda: self.blocked() or self.on_hello())
    self.stop_next()

  def on_hello(self):
    result = self.data.process_result
    if 'MessageName' in result and result['MessageName'] == 'Response':
      logger().debug('MobileBackup2InternalHelloWLink: Hello reply. Protocol version is {0}'.format(result['ProtocolVersion']))
      if result['ErrorCode'] == 0:
        self.next()
      else:
        raise RuntimeError('MobileBackup2InternalHelloWLink: No common version')
    else:
      raise RuntimeError('MobileBackup2InternalHelloWLink: Incorrect reply')


#
# MobileBackup2ConnectUsingDeviceLinkWLink
#

class MobileBackup2ConnectUsingDeviceLinkWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.device_link.connect(self.data.did, self.data.service_port, lambda: self.blocked() or self.next())
    self.stop_next()


#
# MobileBackup2Service
#

class MobileBackup2Service(DeviceLinkService):
  SERVICE_NAME = 'com.apple.mobilebackup2'

  def __init__(self, io_service):
    super().__init__(io_service)

  def hello(self, on_result):
    self.workflow = wl.WorkflowBatch(
      DeviceLinkVersionExchangeWLink(self.data),
      MobileBackup2InternalHelloWLink(self.data),
      wl.ProxyWorkflowLink(on_result))
    self.workflow.start()


#
# MobileBackup2ConnectToWLink
#

class MobileBackup2ConnectToWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.mobilebackup2.connect(self.data.did, self.data.service_port, lambda: self.blocked() or self.next())
    self.stop_next()


#
# MobileBackup2HelloWLink
#

class MobileBackup2HelloWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.mobilebackup2.hello(lambda: self.blocked() or self.next())
    self.stop_next()


#
# AppleFileConduitService
#

class AppleFileConduitService(DeviceLinkService):
  SERVICE_NAME = 'com.apple.afc'

  def __init__(self, io_service):
    super().__init__(io_service)


#
# AppleFileConduitConnectWLink
#

class AppleFileConduitConnectWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.afc.connect(self.data.did, self.data.service_port, lambda: self.blocked() or self.next())
    self.stop_next()


#
# NotificationProxyService
#

class NotificationProxyService(DeviceLinkService):
  SERVICE_NAME = 'com.apple.mobile.notification_proxy'

  def __init__(self, io_service):
    super().__init__(io_service)


#
# NotificationProxyConnectWLink
#

class NotificationProxyConnectWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.notification_proxy.connect(self.data.did, self.data.service_port, lambda: self.blocked() or self.next())
    self.stop_next()


#
# TestBackup
#

class TestBackup:
  def __init__(self, io_service, did, sn):
    self.io_service = SafeIOService(io_service, self.on_exit)
    self.did = did
    self.sn = sn
    self.lockdown = LockdownService(self.io_service)
    self.notification_proxy = NotificationProxyService(self.io_service)
    self.mobilebackup2 = MobileBackup2Service(self.io_service)
    self.afc = AppleFileConduitService(self.io_service)
    self.data = dict(
      io_service=self.io_service,
      lockdown=self.lockdown,
      notification_proxy=self.notification_proxy,
      mobilebackup2=self.mobilebackup2,
      afc=self.afc
    )
 
  def start(self):
    self.io_service.execute(self.on_enter)

  def close(self):
    pass

  def on_enter(self):
    workflow = wl.WorkflowBatch(
      UxbMuxConnectToLockdownWLink(self.data, did=self.did, sn=self.sn),
      LockdownStartAnotherServiceWLink(self.data, service=AppleFileConduitService.SERVICE_NAME, use_escrow_bag=False),
      AppleFileConduitConnectWLink(self.data),
      LockdownStartAnotherServiceWLink(self.data, service=NotificationProxyService.SERVICE_NAME, use_escrow_bag=False),
      NotificationProxyConnectWLink(self.data),
      LockdownStartAnotherServiceWLink(self.data, service=MobileBackup2Service.SERVICE_NAME, use_escrow_bag=True),
      MobileBackup2ConnectToWLink(self.data),
      MobileBackup2HelloWLink(self.data),
      wl.ProxyWorkflowLink(lambda: self.on_exit(None)))
    workflow.start()

  def on_exit(self, e):
    logger().debug('Exit')
    if e:
      import traceback
      logger().error(traceback.format_exc())
      print(e)
    self.lockdown.close()
    self.afc.close()
    self.notification_proxy.close()
    self.mobilebackup2.close()


def configure_argparse():
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers(help='List of commands', dest='command')
  #
  list_parser = subparsers.add_parser('list', help='List')
#  list_parser.set_defaults(func=lis)
  #
  listen_parser = subparsers.add_parser('listen', help='Listen')
  listen_parser.add_argument('--timeout', '-t', type=int, default=10, help='timeout in seconds')
  #
  test_parser = subparsers.add_parser('test', help='Test')
  test_parser.add_argument('--did', type=int, help='did')
  test_parser.add_argument('--sn', type=str, help='sn')
  return parser


def command_list(args, io_service):
  return TestGetDeviceList(io_service)

def command_listen(args, io_service):
  return TestListenForDevices(io_service, args.timeout)

def command_test(args, io_service):
  return TestBackup(io_service, args.did, args.sn)


def Main():
  print("Acronis Mobile Backup")
  configure_logger()
  logger().info('Current platform: {0}'.format(sys.platform))

  commands = {
    'list': command_list,
    'listen': command_listen,
    'test': command_test
  }
  args = configure_argparse().parse_args()

  io_service = IOService()
  cmd = commands[args.command](args, io_service)
  cmd.start()
  io_service.run()

Main()
