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
    self.data.connection = Connection(self.data.io_service, self.data.do_connect())
    self.next()


#
# UsbMuxInternalChangeSessionToUsbMuxWLink
#

class UsbMuxInternalChangeSessionToUsbMuxWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.session = usbmux.UsbMuxSession(self.data.connection)
    self.next()


#
# UsbMuxService
#

class UsbMuxService:
  def __init__(self, io_service, do_connect):
    self.data = dict(io_service=io_service, do_connect=do_connect)
    self.workflow = None

  def connect(self, on_result):
    self.workflow = wl.WorkflowBatch(
      UsbMuxInternalConnectToUsbMuxWLink(self.data),
      UsbMuxInternalChangeSessionToUsbMuxWLink(self.data),
      wl.ProxyWorkflowLink(on_result))
    self.workflow.start()

  def connect_to_service(self, did, port, on_result):
    pass

  def list_devices(self, on_result):
    pass

  def read_buid(self, on_result):
    pass

  def read_pair_record(self, on_rsult):
    pass