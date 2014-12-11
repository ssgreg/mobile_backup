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
import afc
import device_link
import idevice
import lockdown
import mobilebackup2
import usbmux
import wl


def connect():
  if (sys.platform == 'darwin'):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(r'/var/run/usbmuxd')
  else:
    sock = socket.socket()
    sock.connect(('127.0.0.1', 27015))
  return sock


#
# CommonServiceSession
#

class CommonServiceSession:
  def __init__(self, connection):
    self.__channel = lockdown.LockdownPlistChannel(connection)
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
# SessionChangeToCommonService
#

class SessionChangeToCommonService(wl.WorkflowLink):
  def proceed(self):
    self.data.session = CommonServiceSession(self.data.connection)
    self.next()


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
        self.data.session.send(device_link.create_device_link_message_dl_version_ok(major, minor), lambda x: self.blocked() or self.on_version_exchange(x))
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
    logger().debug('DeviceLinkIntern565alProcessMessageWLink: Processing message...')
    self.data.session.send(device_link.create_device_link_message_process_message(self.data.message), lambda x: self.blocked() or self.on_process_message(x))
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
    self.data.device_link.process_message(mobilebackup2.create_mobilebackup2_message_hello(versions), lambda: self.blocked() or self.on_hello())
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
# TestBackup
#

class TestBackup:
  def __init__(self, io_service, did, sn):
    self.io_service = SafeIOService(io_service, self.on_exit)
    self.did = did
    self.sn = sn
    self.directory = idevice.Directory(lambda: Connection(self.io_service, connect()))
    self.data = dict(directory=self.directory)

  def start(self):
    self.io_service.execute(self.on_enter)

  def close(self):
    pass

  def on_enter(self):
    workflow = wl.WorkflowBatch(
      idevice.DirectoryFindObjectWLink(self.data, did=self.did, sn=self.sn),
      idevice.ObjectGetAfcServiceWLink(self.data),
#      idevice.ObjectGetNpServiceWLink(self.data),
      afc.OpenFileWLink(self.data, path='/com.apple.itunes.lock_sync', mode=2),
      wl.ProxyWorkflowLink(lambda: self.on_exit(None)))
    workflow.start()

  def on_exit(self, e):
    logger().debug('Exit')
    if e:
      import traceback  
      logger().error(traceback.format_exc())
      print(e)
    self.directory.close()
    if 'object' in self.data:
      self.data['object'].close()


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
