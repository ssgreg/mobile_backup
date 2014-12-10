# -*- coding: utf-8 -*-
# 
# usbmux.py
# UsbMux service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import plistlib
import struct
#
from io_service import *
from logger import *
from tools import *
import wl


def create_usbmux_message(command):
  pl = dict(
    BundleID = 'org.acronis.usbmuxd',
    ClientVersionString = '1.0.0',
    MessageType = command,
    ProgName = 'Acronis Mobile Backup',
    kLibUSBMuxVersion = 1)
  return pl

def create_usbmux_message_list_devices():
  return create_usbmux_message('ListDevices')

def create_usbmux_message_read_buid():
  return create_usbmux_message('ReadBUID')

def create_usbmux_message_listen():
  return create_usbmux_message('Listen')

def create_usbmux_message_connect(did, port):
  # we should pass the port in the big endian format
  be_port = struct.unpack('>H', struct.pack('@H', port))[0]
  #
  plist_data = create_usbmux_message('Connect')
  plist_data['DeviceID'] = did
  plist_data['PortNumber'] = be_port
  return plist_data

def create_usbmux_message_read_pair_record(sn):
  plist_data = create_usbmux_message('ReadPairRecord')
  plist_data['PairRecordID'] = sn
  return plist_data


#
# UsbMuxHeader
#

class UsbMuxHeader:
  SIZE = 16

  def __init__(self, size=None, version=None, mtype=None, tag=None):
    self.size = size
    self.version = version
    self.mtype = mtype
    self.tag = tag

  def encode(self):
    return struct.pack('<IIII', self.size  + self.SIZE, self.version, self.mtype, self.tag)

  def decode(self, encoded):
    self.size, self.version, self.mtype, self.tag = struct.unpack_from('<IIII', encoded)
    self.size -= self.SIZE


def makeUsbMuxHeader(size=None, version=None, mtype=None, tag=None):
  return UsbMuxHeader(size, version, mtype, tag)


#
# UsbMuxMessageChannel
#

class UsbMuxMessageChannel:
  USBMUX_VERSION = 1

  def __init__(self, connection):
    self.connection = connection
    self.connection.on_ready_to_recv = self.__on_ready_to_recv
    self.on_incoming_message = lambda data, tag, mtype: None
    self.__message_receiver = MessageReceiver(makeUsbMuxHeader, UsbMuxHeader.SIZE)

  def send(self, data, tag, mtype):
    header = UsbMuxHeader(len(data), self.USBMUX_VERSION, mtype, tag)
    self.connection.send(header.encode())
    self.connection.send(data)

  def __on_ready_to_recv(self):
    if self.__message_receiver.recv(self.connection):
      data = self.__message_receiver.data
      header = self.__message_receiver.header
      self.__message_receiver.reset()
      self.on_incoming_message(data, header.tag, header.mtype)


#
# UsbMuxPlistChannel
#

class UsbMuxPlistChannel:
  PLIST_MTYPE = 8

  def __init__(self, connection):
    self.internal_channel = UsbMuxMessageChannel(connection)
    self.internal_channel.on_incoming_message = self.__on_incoming_message
    self.on_incoming_plist = lambda plist_data, tag: None

  def send(self, plist_data, tag):
    self.internal_channel.send(plistlib.dumps(plist_data), tag, self.PLIST_MTYPE)

  def __on_incoming_message(self, data, tag, mtype):
    if mtype != self.PLIST_MTYPE:
      raise RuntimeError('Unsupported message type.')
    plist_data = plistlib.loads(data)
    self.on_incoming_plist(plist_data, tag)


#
# UsbMuxSession
#

class UsbMuxSession:
  TAG_NOTIFICATION = 0
  TAG_FIRST = 0x1000000

  def __init__(self, connection):
    self.__channel = UsbMuxPlistChannel(connection)
    self.__channel.on_incoming_plist = self.__on_incoming_plist
    self.on_notification = lambda plist_data: None
    self.callbacks = {}
    self.tag = self.TAG_FIRST
    logger().debug('UsbMux session has started.')

  def send(self, plist_data, on_result):
    self.callbacks[self.tag] = on_result
    self.__channel.send(plist_data, self.tag)
    self.tag += 1

  def __on_incoming_plist(self, plist_data, tag):
    if tag == self.TAG_NOTIFICATION:
      self.on_notification(plist_data)
    else:
      self.callbacks[tag](plist_data)
      del self.callbacks[tag]


#
# UsbMuxInternalConnectToUsbMuxWLink
#

class UsbMuxInternalConnectToUsbMuxWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.connection = self.data.connect()
    self.next()


#
# UsbMuxInternalChangeSessionToUsbMuxWLink
#

class UsbMuxInternalChangeSessionToUsbMuxWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.session = UsbMuxSession(self.data.connection)
    self.next()


#
# UsbMuxInternalListDevicesWLink
#

class UsbMuxInternalListDevicesWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('UsbMuxInternalListDevicesWLink: Getting device list...')
    self.data.session.send(create_usbmux_message_list_devices(), lambda x: self.blocked() or self.on_list_devices(x))
    self.stop_next()

  def on_list_devices(self, result):
    if 'DeviceList' in result:
      self.data.devices = [UsbMuxDevice(self.data.usbmux, d, self.data.buid) for d in result['DeviceList']]
      # remove all non-USB devices
      self.data.devices = [d for d in self.data.devices if d.connected_via_usb()]
      #
      logger().debug('UsbMuxInternalListDevicesWLink: Done. Count = {0}'.format(len(self.data.devices)))
      self.next()
    else:
      raise RuntimeError('Failed to list devices')


#
# UsbMuxInternalReadBuidWLink
#

class UsbMuxInternalReadBuidWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('UsbMuxInternalReadBuidWLink: Reading BUID')
    self.data.session.send(create_usbmux_message_read_buid(), lambda x: self.blocked() or self.on_read_buid(x))
    self.stop_next()

  def on_read_buid(self, result):
    if 'BUID' in result:
      self.data.buid = result['BUID']
      logger().debug('UsbMuxInternalReadBuidWLink: Done. BUID = {0}'.format(self.data.buid))
      self.next();
    else:
      raise RuntimeError('Failed to read BUID')


#
# UsbMuxInternalReadPairRecordWLink
#

class UsbMuxInternalReadPairRecordWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('UsbMuxInternalReadPairRecordWLink: Reading pair record of a device with a sn = {0}'.format(self.data.sn))
    self.data.session.send(create_usbmux_message_read_pair_record(self.data.sn), lambda x: self.blocked() or self.on_get_pair_record(x))
    self.stop_next()

  def on_get_pair_record(self, result):
    if 'PairRecordData' in result:
      self.data.pair_record_data = plistlib.loads(result['PairRecordData'])
      logger().debug('UsbMuxInternalReadPairRecordWLink: Done. HostID = {0}'.format(self.data.pair_record_data['HostID']))
      self.next();
    else:
      raise RuntimeError('Failed to read pair record')


#
# UsbMuxInternalConnectToServiceWLink
#

class UsbMuxInternalConnectToServiceWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('UsbMuxInternalConnectToServiceWLink: Connecting to a service, did = {0} port = {1}'.format(self.data.did, self.data.port))
    self.data.session.send(create_usbmux_message_connect(self.data.did, self.data.port), lambda x: self.blocked() or self.on_connect(x))
    self.stop_next()

  def on_connect(self, confirmation):
    if confirmation['Number'] == 0:
      logger().debug('UsbMuxInternalConnectToServiceWLink: Done.')
      self.next();
    else:
      raise RuntimeError('Failed to connect with an error = {0}'.format(confirmation['Number']))


#
# UsbMuxService
#

class UsbMuxService:
  def __init__(self, connect, on_result):
    logger().debug('UsbMuxService: Connecting to usbmux service...')
    self.data = dict(connect=connect, usbmux=self)
    #
    self.workflow = wl.WorkflowBatch(
      UsbMuxInternalConnectToUsbMuxWLink(self.data),
      UsbMuxInternalChangeSessionToUsbMuxWLink(self.data),
    )
    self.workflow.start()

  def connect_to_service(self, did, port, on_result):
    data = dict(self.data)
    self.workflow = wl.WorkflowBatch(
      UsbMuxInternalConnectToUsbMuxWLink(data),
      UsbMuxInternalChangeSessionToUsbMuxWLink(data),
      UsbMuxInternalConnectToServiceWLink(data, did=did, port=port),
      wl.ProxyWorkflowLink(lambda: on_result(data['connection']))
    )
    self.workflow.start()

  def list_devices(self, on_result):
    self.workflow = wl.WorkflowBatch(
      UsbMuxReadBuidWLink(self.data),
      UsbMuxInternalListDevicesWLink(self.data),
      wl.ProxyWorkflowLink(lambda: on_result(self.data['devices']))
    )
    self.workflow.start()

  def read_buid(self, on_result):
    self.workflow = wl.WorkflowBatch(
      UsbMuxInternalReadBuidWLink(self.data),
      wl.ProxyWorkflowLink(lambda: on_result(self.data['buid']))
    )
    self.workflow.start()

  def read_pair_record(self, sn, on_result):
    self.workflow = wl.WorkflowBatch(
      UsbMuxInternalReadPairRecordWLink(self.data, sn=sn),
      wl.ProxyWorkflowLink(lambda: on_result(self.data['pair_record_data']))
    )
    self.workflow.start()

  def close(self):
    if 'connection' in self.data:
      logger().debug('Closing usbmux connection...')
      self.data['connection'].close()
      self.data['connection'] = None


#
# UsbMuxMakeServiceWLink
#

class UsbMuxMakeServiceWLink(wl.WorkflowLink):
  def proceed(self):
    # TODO: Make connection async
    self.data.usbmux = UsbMuxService(self.data.connect_to_usbmux, None)
    self.next()


#
# UsbMuxListDevicesWLink
#

class UsbMuxListDevicesWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.usbmux.list_devices(lambda x: self.blocked() or self.on_list_devices(x))
    self.stop_next()

  def on_list_devices(self, devices):
    self.data.devices = devices
    self.next()


#
# UsbMuxReadBuidWLink
#

class UsbMuxReadBuidWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.usbmux.read_buid(lambda x: self.blocked() or self.on_read_buid(x))
    self.stop_next()

  def on_read_buid(self, buid):
    self.data.buid = buid
    self.next()


#
# UsbMuxReadPairRecordWLink
#

class UsbMuxReadPairRecordWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.usbmux.read_pair_record(self.data.device.sn, lambda x: self.blocked() or self.on_read_pair_record(x))
    self.stop_next()

  def on_read_pair_record(self, data):
    self.data.pair_record_data = data
    self.next()


#
# UsbMuxConnectToServiceWLink
#

class UsbMuxConnectToServiceWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.usbmux.connect_to_service(self.data.did, self.data.port, lambda x: self.blocked() or self.on_connect_to_service(x))
    self.stop_next()

  def on_connect_to_service(self, connection):
    self.data.service_connection = data
    self.next()


#
# UsbMuxDevice
#

class UsbMuxDevice:
  def __init__(self, usbmux, info, buid):
    self.usbmux = usbmux
    self.__info = info
    self.__buid = buid

  def connect_to_service(self, port, on_result):
    self.usbmux.connect_to_service(self.did, port, on_result)

  def read_pair_record(self, on_result):
    self.usbmux.read_pair_record(self.sn, on_result)

  def connected_via_usb(self):
    return self.connection_type == 'USB'

  def display(self):
    return '(UsbMuxDevice | did = {0} | sn = {1} | type = {2})'.format(self.did, self.sn, self.connection_type)

  @property
  def buid(self):
    return self.__buid

  @property
  def did(self):
    return self.__info['DeviceID']

  @property
  def sn(self):
    return self.__info['Properties']['SerialNumber']

  @property
  def connection_type(self):
    # USB or Network
    return self.__info['Properties']['ConnectionType']

  @property
  def info(self):
    return self.__info


#
# UsbMuxDeviceConnectToServiceWLink
#

class UsbMuxDeviceConnectToServiceWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.device.connect_to_service(self.data.port, lambda x: self.blocked() or self.on_connect_to_service(x))
    self.stop_next()

  def on_connect_to_service(self, connection):
    self.data.service_connection = connection
    self.next()


#
# UsbMuxDeviceReadPairRecordWLink
#

class UsbMuxDeviceReadPairRecordWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.device.read_pair_record(lambda x: self.blocked() or self.on_read_pair_record(x))
    self.stop_next()

  def on_read_pair_record(self, pair_record_data):
    self.data.pair_record_data = pair_record_data
    self.next()
