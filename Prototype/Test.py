import socket
import plist
import struct
import binascii
import sched
import select
import time
import collections
import sys
import logging
import logging.config
import wl


def configure_logger():
  logging.config.fileConfig('logging.ini')

def logger():
  return logging.getLogger(__name__)


#
# IOService
#

class IOService(object):
  def __init__(self):
    XHolder = collections.namedtuple('XHolder', 'ios, x')
    self.scheduler = sched.scheduler(time.time, self.__process_io)
    self.__rxh = XHolder([], {})
    self.__txh = XHolder([], {})
    self.__xxh = XHolder([], {})

  def register(self, io, rx=None, tx=None, xx=None):
    for xh, x in ((self.__rxh, rx), (self.__txh, tx), (self.__xxh, xx)):
      if x:
        xh.ios.append(io)
        xh.x[io] = x

  def unregister(self, io):
    for xh in (self.__rxh, self.__txh, self.__xxh):
      xh.ios[:] = [x for x in xh.ios if x != io]
      xh.x.pop(io, None)

  def run(self):
    while True:
      self.scheduler.run()
      if len(self.__rxh.ios) != 0:
        self.__process_io()
      else:
        break

  def stopped(self):
    return self.stop_flag

  def __process_io(self, timeout=None):
    rios, tios, xios = select.select(self.__rxh.ios, self.__txh.ios, self.__xxh.ios, timeout)
    for xh, signaled_ios in ((self.__rxh, rios), (self.__txh, tios), (self.__xxh, xios)):
      for io in signaled_ios:
        xh.x[io]()


#
# Connection
#

class Connection(object):
  def __init__(self, service, io):
    self.__io = io
    self.__service = service
    self.__service.register(io, self.__on_ready_to_recv)
    self.on_ready_to_recv = lambda: None

  def close(self):
    self.__service.unregister(self.__io)
    self.__io.close()

  def send(self, data):
    # print('CON[{}] <-- ({}) {}'.format(id(self.__io), len(data), binascii.hexlify(data)))
    self.__io.send(data)

  def recv(self, size):
#    print('CON[{}] --> ({}) {}'.format(id(self.io), len(data), binascii.hexlify(data)))
    data = self.__io.recv(size)
    if not data:
      raise RuntimeError('Connection forcibly closed.')
    return data

  def __on_ready_to_recv(self):
    self.on_ready_to_recv()


#
# UsbMuxHeader
#

class UsbMuxHeader(object):
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
# PlistHeader
#

class PlistHeader(object):
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
# MessageReceiver
#

class MessageReceiver(object):
  def __init__(self, header_factory=None, header_size=None):
    self.__header_factory = header_factory
    self.__header_size = header_size
    self.reset()

  def recv(self, connection):
    if not self.header:
      if len(self.data) < self.__header_size:
        self.data += connection.recv(self.__header_size - len(self.data))
        if len(self.data) == self.__header_size:
          self.header = self.__header_factory()
          self.header.decode(self.data)
          self.data = b''
    if self.header:
      if len(self.data) < self.header.size:
        self.data += connection.recv(self.header.size - len(self.data))
        if len(self.data) == self.header.size:
          return True
    return False

  def reset(self):
    self.header = None
    self.data = b''


#
# UsbMuxMessageChannel
#

class UsbMuxMessageChannel(object):
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
# PlistMessageChannel
#

class PlistMessageChannel(object):
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
# UsbMuxPlistChannel
#

class UsbMuxPlistChannel(object):
  PLIST_MTYPE = 8

  def __init__(self, connection):
    self.internal_channel = UsbMuxMessageChannel(connection)
    self.internal_channel.on_incoming_message = self.__on_incoming_message
    self.on_incoming_plist = lambda plist_data, tag: None

  def send(self, plist_data, tag):
    self.internal_channel.send(plist.dumps(plist_data).encode('utf-8'), tag, self.PLIST_MTYPE)

  def __on_incoming_message(self, data, tag, mtype):
    if mtype != self.PLIST_MTYPE:
      raise RuntimeError('Unsupported message type.')
    plist_data = plist.loads(data.decode('utf-8'))
    self.on_incoming_plist(plist_data, tag)


#
# PlistChannel
#

class PlistChannel(object):
  def __init__(self, connection):
    self.internal_channel = PlistMessageChannel(connection)
    self.internal_channel.on_incoming_message = self.__on_incoming_message
    self.on_incoming_plist = lambda plist_data: None

  def send(self, plist_data):
    self.internal_channel.send(plist.dumps(plist_data).encode('utf-8'))

  def __on_incoming_message(self, data):
    plist_data = plist.loads(data.decode('utf-8'))
    self.on_incoming_plist(plist_data)


#
# UsbMuxSession
#

class UsbMuxSession(object):
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
# LockdownSession
#

class LockdownSession(object):
  FIELD_REQUEST = 'Request'

  def __init__(self, connection):
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
      raise RuntimeError('Lockdown recieved incorrect data.')
    # store callback locally to avoid problems with calling 'send' in callback
    callback = self.callback
    self.reset()
    callback(plist_data)

  def reset(self):
    self.callback = None
    self.original_request = ''


def connect():
  if (sys.platform == 'darwin'):
    logger().info('Using UNIX socket to connect to the usbmuxd.')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(r'/var/run/usbmuxd')
  else:
    logger().info('Connecting to the apple service...')
    sock = socket.socket()
    sock.connect('127.0.0.1', 27015)
  return sock


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
  plist_data = create_usbmux_message('Connect')
  plist_data['DeviceID'] = did
  plist_data['PortNumber'] = port
  return plist_data

def create_usbmux_message_read_pair_record(sn):
  plist_data = create_usbmux_message('ReadPairRecord')
  plist_data['PairRecordID'] = sn
  return plist_data

def create_lockdown_message_query_type():
  return dict(Request = 'QueryType')

def create_lockdown_message_validate_pair(host_id):
  return dict(
    PairRecord = dict(HostID = host_id),
    Request = 'ValidatePair',
    ProtocolVersion = '2')


def print_device_info(device):
  print '\t', 'did:', device.DeviceID, '| sn:', device.Properties.SerialNumber, '| contype:', device.Properties.ConnectionType, '| pid: {0}'.format(device.Properties.ProductID) if 'ProductID' in device.Properties else ''


#
# TestGetDeviceList
#

class TestGetDeviceList(object):
  def __init__(self, io_service):
    self.connection = Connection(io_service, connect())
    self.internal_session = UsbMuxSession(self.connection)
    logger().debug('Getting device list...')
    self.internal_session.send(create_usbmux_message_list_devices(), self.on_devices)

  def on_devices(self, devices):
    print 'device list:'
    for i in devices.DeviceList:
      print_device_info(i)
    #
    logger().debug('Getting buid...')
    self.internal_session.send(create_usbmux_message_read_buid(), self.on_buid)

  def on_buid(self, buid):
    print 'buid:'
    print '\t', buid
    self.close()

  def close(self):
    self.connection.close()


#
# TestListenForDevices
#

class TestListenForDevices(object):
  def __init__(self, io_service):
    io_service.scheduler.enter(10, 1, self.close, ())
    self.connection = Connection(io_service, connect())
    self.internal_session = UsbMuxSession(self.connection)
    self.internal_session.on_notification = self.on_notification
    #
    logger().debug('Listening for devices...')
    self.internal_session.send(create_usbmux_message_listen(), self.on_listen)

  def on_listen(self, confirmation):
    logger().debug('Listen confirmed')

  def on_notification(self, notification):
    if notification.MessageType == 'Attached':
      print 'Device attached:'
      print_device_info(notification)
    else:
      print 'Device dettached:'
      print '\t', 'did:', notification.DeviceID

  def close(self):
    self.connection.close()


#
# ConnectToUsbMuxdWLink
#

class ConnectToUsbMuxdWLink(wl.WorkflowLink):
  def __init__(self, data):
    super(ConnectToUsbMuxdWLink, self).__init__()
    self.data = data

  def proceed(self):
    self.data.connection = Connection(self.data.io_service, connect())
    self.data.session = UsbMuxSession(self.data.connection)
    self.next()


#
# ReadPairRecordWLink
#

class ReadPairRecordWLink(wl.WorkflowLink):
  def __init__(self, data):
    super(ReadPairRecordWLink, self).__init__()
    self.data = data

  def proceed(self):
    logger().debug('Reading pair record of a device with a sn = {0}'.format(self.data.sn))
    self.data.session.send(create_usbmux_message_read_pair_record(self.data.sn), self.on_get_pair_record)
  
  def on_get_pair_record(self, result):
    if 'PairRecordData' not in result:
      print 'Invalid pair record result.'
      self.stopOthers()
    else:
      self.data.pair_record_data = plist.loads(result.PairRecordData.data.decode('utf-8'))
      logger().debug('Done. HostID = {0}'.format(self.data.pair_record_data.HostID))
      self.next();


#
# ReadBuidWLink
#

class ReadBuidWLink(wl.WorkflowLink):
  def __init__(self, data):
    super(ReadBuidWLink, self).__init__()
    self.data = data

  def proceed(self):
    logger().debug('Reading BUID')
    self.data.session.send(create_usbmux_message_read_buid(), self.on_read_buid)
  
  def on_read_buid(self, result):
    if 'BUID' not in result:
      print 'Invalid BUID result.'
      self.stopOthers()
    else:
      self.data.buid = result.BUID
      logger().debug('Done. BUID = {0}'.format(self.data.buid))
      self.next();


#
# ConnectToLockdownWLink
#

class ConnectToLockdownWLink(wl.WorkflowLink):
  LOCKDOWN_SERVICE_PORT = 32498

  def __init__(self, data):
    super(ConnectToLockdownWLink, self).__init__()
    self.data = data

  def proceed(self):
    logger().debug('Connecting to the Lockdown service of a device with did = {0}'.format(self.data.did))
    self.data.session.send(create_usbmux_message_connect(self.data.did, self.LOCKDOWN_SERVICE_PORT), self.on_connect_to_lockdown)

  def on_connect_to_lockdown(self, confirmation):
    if confirmation.Number != 0:
      print 'Failed to connect with an error =', confirmation.Number
      self.stopOthers()
    else:
      logger().debug('Done')
      self.data.session = LockdownSession(self.data.connection)
      self.next();


#
# CheckLockdownTypeWLink
#

class CheckLockdownTypeWLink(wl.WorkflowLink):
  LOCKDOWN_SERVICE_TYPE = 'com.apple.mobile.lockdown'

  def __init__(self, data):
    super(CheckLockdownTypeWLink, self).__init__()
    self.data = data

  def proceed(self):
    logger().debug('Checking service type...')
    self.data.session.send(create_lockdown_message_query_type(), self.on_check_lockdown_type)

  def on_check_lockdown_type(self, result):
    if 'Type' not in result or result.Type != self.LOCKDOWN_SERVICE_TYPE:
      print 'Failed to query the lockdown service type. Answer:', result
      self.stopOthers()
    else:
      logger().debug('Done. Service type is: {0}'.format(result.Type))
      self.next();


#
# ValidatePairRecordWLink
#

class ValidatePairRecordWLink(wl.WorkflowLink):
  def __init__(self, data):
    super(ValidatePairRecordWLink, self).__init__()
    self.data = data

  def proceed(self):
    logger().debug('Validating pair record with HostID = {0}'.format(self.data.pair_record_data['HostID']))
    self.data.session.send(create_lockdown_message_validate_pair(self.data.pair_record_data['HostID']), self.on_validate_pair_record)

  def on_validate_pair_record(self, result):
    if 'Error' in result:
      print 'Failed to validate pair. Error:', result['Error']
      self.stopOthers()
    else:
      logger().debug('Done.')
      self.next();


#
# CloseWLink
#

class CloseWLink(wl.WorkflowLink):
  def __init__(self, data):
    super(CloseWLink, self).__init__()
    self.data = data

  def block(self):
    self.data.close()

  def proceed(self):
    self.block()


#
# TestConnectToLockdown
#

class TestConnectToLockdown(object):
  def __init__(self, io_service, did, sn):
    self.io_service = io_service
    self.did = did
    self.sn = sn
    self.connection = None
    self.service = None
    self.pair_record_data = None
    #
    workflow = wl.link_workflow(
      ConnectToUsbMuxdWLink(self),
      ReadBuidWLink(self),
      ReadPairRecordWLink(self),
      ConnectToLockdownWLink(self),
      CheckLockdownTypeWLink(self),
      ValidatePairRecordWLink(self),
      CloseWLink(self))
    workflow.start()

  def close(self):
    self.connection.close()


def Main():
  print "Acronis Mobile Backup prototype for Apple devices."
  configure_logger()
  logger().info('Current platform: {0}'.format(sys.platform))

  io_service = IOService()
#  TestGetDeviceList(io_service)
#  TestListenForDevices(io_service)
  TestConnectToLockdown(io_service, 998, 'fe4121986da469cbd4ff59fce5cb8383aee5e120')
  io_service.run()


Main()


# Devices that accessed only by network are not enumerates via listen session.


# {'DeviceList':
#   [
#     {'DeviceID': 100,
#      'MessageType': 'Attached',
#      'Properties':
#        {'SerialNumber': 'fe4121986da469cbd4ff59fce5cb8383aee5e120',
#         'ConnectionType': 'USB',
#         'LocationID': 2685599744,
#         'ConnectionSpeed': 480000000,
#         'DeviceID': 100,
#         'ProductID': 4779}},
#     {'DeviceID': 56,
#      'MessageType': 'Attached',
#      'Properties':
#        {'SerialNumber': '021257f38375288271c3a8ec7ee951b69a8e4e9f',
#         'ConnectionType': 'USB',
#         'LocationID': 2685468672,
#         'ConnectionSpeed': 480000000,
#         'DeviceID': 56,
#         'ProductID': 4779}},
#     {'DeviceID': 55,
#      'MessageType': 'Attached',
#      'Properties':
#        {'NetworkAddress': Data('\x1c\x1e\x00\x00\x00\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00\x04N\xf1\xeb\xeb\x1a.6\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
#         'SerialNumber': '021257f38375288271c3a8ec7ee951b69a8e4e9f',
#         'InterfaceIndex': 4,
#         'ConnectionType': 'Network',
#         'EscapedFullServiceName': 'a8:5b:78:15:0c:05@fe80::aa5b:78ff:fe15:c05._apple-mobdev2._tcp.local.',
#         'DeviceID': 55}}
#   ]
# }

#
# listen notification: (device detached)
# {'DeviceID': 369, 'MessageType': 'Detached'}
#

# connect to lockdown:
# to correct device id:
# {'Number': 0, 'MessageType': 'Result'}
# to incorrect device id:
# {'Number': 2, 'MessageType': 'Result'}

# query service type:
# {'Type': 'com.apple.mobile.lockdown', 'Request': 'QueryType'}

# read pair data
#   {'RootPrivateKey':
#     Data('-----BEGIN RSA PRIVATE KEY-----
#     MIIEowIBAAKCAQEAsZd2T8AgjWz43D+QGLaT7linU4PvvcpPeLfb/yWMtuRRj3nn
#     j4ObURsOVt/wh4sILIMGT9gmzB6S3L4QYdv982jox3fbDRJOoLO1XgTSI/wLhLfS
#     fZFOtz2mH8uALAMQtjTtz8JRgrAC3ttbM8JqeXL88MI3rzx8OnJ/+ZAJa3sUBQW7
#     sLruC6gk8qJDg68iAbRhGhKAGzXgy0y2oXdRxraNsuLB9+QD7SnpBVQF5dbb/Fg7
#     1/tmrdP6oGUf7NcWbWX313WX3mOJpyvIjwQ/KHCvlJCWezDljE6uHV4cbHLBmOIQ
#     yfMYpKGHkyIGVbzXrNPeKnHoNItvyTB2fUhU6QIDAQABAoIBAAsMPhr1+9BwgAbL
#     mX5AFXHVaAtlAMwQwuLipTf5MQjLqVtAnSwrZsUj5r92zPLRrl9+gy0CaF94Y3CC
#     DmjYE7NJynlmNmVYxzVuGJFRwXTloB3QhbK0EG6L0kLWGRIj2q1LG6Q6FXII2xTc
#     Fo9gv9jwU1Xy7x3iqGPGbbmrwTpDYlJlFWWAmeFMeu6ydS4wX3nB3UUY3VCA+2VI
#     YpIe6KVz5ecg8TrV+n/MI0VHNQfpoNK7+Pp87fwmD+81KpE3uFnb6iB4j9+9UMH7
#     E8NUHkVioZYotNqvfCsRr519+XNrd3ZBZoAMKEkZE1YFcezQlCw64NDEN/9ILEJT
#     pxsc+PUCgYEA2BeGsIpwAUDKy4QnfdSBIimuDNx7dK1M78MB7zAJGdjoAHwcVZsA
#     3F75Ku6qOaLoTXkv5Fn1c2nNmf8il4szsHEZ4cmu8QDivxJDzC2JsGhcvijA1da/
#     C28egHa61QsWCG1VgxCBcTJM+nFCiskEX6v4P1aeCB/T+fCwjdK4AtMCgYEA0mO0
#     7nrfZv2TzmaLGwoxOQncEZ8YrsoBj+CvQRnOffs1whUg8h9GqFq5b1J5LZSU+FsL
#     +mgdZ4zcHRzDlTrAn5dwEQGdMBunkKtlVVSdLkVz488A2r0pxt121pxtuLGdV8xd
#     ugbjGNTj0FAZ4cHvmavl6lMqisdo7/F/AKrPW9MCgYEAz8GmtFsVHo9NqmePlHHY
#     CaFq/mCIrX/kxWuGk5FqXphlTfoFP+S76iPBiZ5WuP1APSQzgGdhDip+Cv36Ixsp
#     ggzrZmKCuKEyX6PO3SI3DAz6hbUm2TETEoouGDKOpD95WnbLzSv0V4GV8v8ri8WC
#     V/09up+rZoI7SkU3adNbKRMCgYAcN89OpSBNmfk3F73UlJthgRcJLgOLfgCToZkf
#     7Cwr7YOaUmcm0lcRwYlZiwBBwsnwPZXvsgMvnk7vgKoi28x2G0OmpEbG6w6gcryW
#     o1CpohsXFO6SaAiwaYfE5Ro6SWhHHFv91WqkK/maOQQfqXlPbSTbNuhf0LscY5Gb
#     L028jQKBgBHSPz7ICudpJMwLaYcbbJ1FguWuF9C4AaGUj/ZsCjtqLX0IlwjYSPtA
#     eHEX5aNZNP8swVpGU46yAnuh3xcYa4vX14MwYFB52wnNvPs8LnLqcfDoVJjYcIcx
#     lMkhzUI997aSFPxP7FC1f2HCg7+kBcbVHkFQU91s62VZ0juA/yN0
#     -----END RSA PRIVATE KEY-----'),
#   'HostCertificate': Data('-----BEGIN CERTIFICATE-----
#     MIICujCCAaKgAwIBAgIBADANBgkqhkiG9w0BAQUFADAAMB4XDTE0MTEyMDE0MjMy
#     MFoXDTI0MTExNzE0MjMyMFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
#     ggEBAPUJQ4eh9TfKQkuk7ksyGzMnJ+15kwX0PgTewVZdrH4oe31+QxOzNc1+LNQe
#     QUilZz6RoMC2qZrmbjhkypeSPQBbeKVbd18YsP0iXfPmZ0W4npvQGCGsgJpuVgrS
#     8IW6tWimwMtwKETqrFbGJx4HGJqwQQcvRqLLC+jIIEbvuG2Kx1wC1iwckrEUfzjk
#     +w1akiN+T1KfbqS6WpNSzTFKCusWOWrrM0xT7oZEmhrHXRShti2qpnGxORwF6RqU
#     TSnn30qfwEE2DizZ9Qqz4F3JwiF0KwQKmnMBNX3sgwRQXFq90tcNB2UvtHbvhWwm
#     nNLRRFJq1vb3aAcuMNSK3By0nQ0CAwEAAaM/MD0wDAYDVR0TAQH/BAIwADAdBgNV
#     HQ4EFgQUpTcgAL+bx478gtYGY3B+VTWEwCMwDgYDVR0PAQH/BAQDAgWgMA0GCSqG
#     SIb3DQEBBQUAA4IBAQBUC2iVkuwS963ja7xWXWPtcc8GmV12mkKbC2efBxHnLkOL
#     bw2beAe8wySIXRhvSs4WxsuqMl/G3M8YZ1MaakC2fpPsE51bXS8Pgttc3E2+C2sr
#     UiTm8ftvS17TLlr/xUYlW/D0hM9T3IRRK98iH7YbSqYEQxT15IRziW8liyFtAXdK
#     lKQKWw+OjFwukVRzV3qiNaZJfYpHz65UHkVNjTp7AiXfMZTkD2Q2cnX6QF6Vk11w
#     nUNm86rU1ZCe0XEwt1iGxqmGLiwwGmZ56lBxMB77kjycoBYkICJcS26ehxIim7Qz
#     fjBeLav2dLaOIhFQ2njti+xJqUcU69Vp26l89uNH
#     -----END CERTIFICATE-----'),
#   'HostID': '670A85A0-D184-46F1-B056-B7A15792EACD',
#   'DeviceCertificate': Data('-----BEGIN CERTIFICATE-----
#     MIICNjCCAR6gAwIBAgIBADANBgkqhkiG9w0BAQUFADAAMB4XDTE0MTEyMDE0MjMy
#     MFoXDTI0MTExNzE0MjMyMFowADCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
#     xEUWc3ECvEqN0PIcsBs9oHpja5CC3Ttm3ltcu52Xxv3vY5ogq0saTSzHenmiy4lF
#     NFJ7s/PchKPEy/2J+ISPuOXBu1y4xQSk0cGH3zS38pGeLLk/jVm88FTl4xmm6gFm
#     lDSzWpEfXdDYvbo04l4s7+ej7ltuf4viwc9fde2WKxMCAwEAAaM/MD0wDAYDVR0T
#     AQH/BAIwADAdBgNVHQ4EFgQU7PsLUELmKkHClR6fYsFjscWgx78wDgYDVR0PAQH/
#     BAQDAgWgMA0GCSqGSIb3DQEBBQUAA4IBAQBx/+8Pu2GPm3ieFMIhxxRgYkvcj5kt
#     aNGV+oLJ2+ogTh38EUSnQb+s663C+vbLTB7XRRBoe2piHVIjYOTPnwMdeTHFOTnH
#     d2JHTcOhkoULMIXOc9BavaCvWOmdU8da5UTd0qKEwKGeKWBizg7J1Rpp70k0y1Bj
#     RNfxMLBBy2yO8RGNEPIq2paBt8N9espueqKAf+N4Z21OMFfbfvIDFy4NyQpnqgjQ
#     7F2+1qf064NDMsT4iNNN0ANVR3s3vOgvBQWqdwtavYNwuBIVvCHKnmofqIifuFbw
#     HQO/+WNRLoV3FHrt6yJi0XLWu7Pcz30ZR3N1+NpJVRqBEoZfOtlWOwHZ
#     -----END CERTIFICATE-----'),
# 'EscrowBag': Data(':0\xbdmR\xc7&\xc0\x9eu\x9d\xc0\xac\xc9}\xed`\xa0\xb9\xe7\xfcf\xb5\xf6\x8bH\xb2\xf6j\xe5<u'),
# 'HostPrivateKey': Data('-----BEGIN RSA PRIVATE KEY-----
#     MIIEogIBAAKCAQEA9QlDh6H1N8pCS6TuSzIbMycn7XmTBfQ+BN7BVl2sfih7fX5D
#     E7M1zX4s1B5BSKVnPpGgwLapmuZuOGTKl5I9AFt4pVt3Xxiw/SJd8+ZnRbiem9AY
#     IayAmm5WCtLwhbq1aKbAy3AoROqsVsYnHgcYmrBBBy9GossL6MggRu+4bYrHXALW
#     LBySsRR/OOT7DVqSI35PUp9upLpak1LNMUoK6xY5auszTFPuhkSaGsddFKG2Laqm
#     cbE5HAXpGpRNKeffSp/AQTYOLNn1CrPgXcnCIXQrBAqacwE1feyDBFBcWr3S1w0H
#     ZS+0du+FbCac0tFEUmrW9vdoBy4w1IrcHLSdDQIDAQABAoIBADMR0jRDihMtoXGY
#     l12uvMKFh6nT69OS2xYywwLYFSpaD5rRJPPHJxCEGp2/DIYyivkcau+fYmv5WMGC
#     KEM85F/dsKBuFswIHmMztXcu7xk16EC7NzxVcpw9IMuyuRR2HHcKQiZkYtAyROb0
#     95QnkHY1A+iWbtdhEENc6nU+YybZHFifFAfyGRkhLMntGnzI0vt72KRB+lqMhcDG
#     bGFHbEw+m2fgUk4oldn/+CkgPNsiUT8ylioPRs1oCbyGEKdNRQhBnfN1kE9VC9oe
#     oFUnfr2ilSPxJlJ8mfK1nLS9PZesseVMFXuv3QFjIAZYp+rwpAxCu1GX3tIOnXYh
#     ZwWYdGECgYEA/fOB5cRbozhywd5BqVRXGBLlHZ/27PdjSA79qX4XSNRTeh6oZgUP
#     arxdaV6wNQJJzv5a+7wnZjsSKdEHRFixlCEGfm+utybs+skAShre1fN3tZtA72s3
#     diiys2CIKnBwPBahmQKZIC7NAImbDp/JT5C7+pgfZAnnfxJeg+S9wOUCgYEA9wNY
#     DNFrfSOv2qVwsFEZ0mjvB/nKxk0esKiAcydijwqUf32FRvGi8BuVxWo8V2hUVbxL
#     FkI1j7Gcvj73HLIjkFlSq4XugF7VBYSCMVaxpfgFcLuRFJMegqPIYBkllM0A7Cj7
#     noT5Q0Xwhp5/hJxjrkTYYfpJyrbo4Ty/+WbZMQkCgYA0w9C8neTwb/0gHP8FoNmL
#     zfk/A4q5x9kgEsVP3zwVTNCfchlJQUnnwoWiLCNukDAnyx+6aGjDTAjFGYJqCAe1
#     oHsJ8EicE4Fvxi3CN/0O9UxtNnnyhRN8AI7IyIjiUIRxZ75h3XFVh4Pe1bia/EZG
#     uurj8ZGsJoasF3P98ZwfpQKBgCzItGwOg/h6QeXYXOf6rD3TvJKrnTH6xXet9Svr
#     lhjtCCNdNI66PJpfxfW23x3R0oiAzPRKKL/Wqd5sOA1B1uTS7QQgEi/AAcswTRJ4
#     71hx8TqRJyqdychRvYB+zqt9x48JlyUUYsTpp0Qg9GmsmP39iWWqJTrVkr9TblLf
#     bL1RAoGAepEPKv0vn6N9xsz1Owmbvm5FILRUuPKn26xjjnYdd6bXEISCKETEOE7o
#     KHS+lZMNaDPgSxlxNrgMwIDqHsNBpcVum5VqARasrrXXO+TgxbD2ysHBMi1ruRbs
#     qL4RYdOSXBcEcJOuoqeBshh6Ms4IqvwSEL2fRv6DcEvA1rPCM+k=
#     -----END RSA PRIVATE KEY-----'),
#   'SystemBUID': 'DE366373-309C-42BC-A0C3-4EA67FC8EB08',
#   'RootCertificate': Data('-----BEGIN CERTIFICATE-----
#     MIICrTCCAZWgAwIBAgIBADANBgkqhkiG9w0BAQUFADAAMB4XDTE0MTEyMDE0MjMy
#     MFoXDTI0MTExNzE0MjMyMFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
#     ggEBALGXdk/AII1s+Nw/kBi2k+5Yp1OD773KT3i32/8ljLbkUY9554+Dm1EbDlbf
#     8IeLCCyDBk/YJswekty+EGHb/fNo6Md32w0STqCztV4E0iP8C4S30n2RTrc9ph/L
#     gCwDELY07c/CUYKwAt7bWzPCanly/PDCN688fDpyf/mQCWt7FAUFu7C67guoJPKi
#     Q4OvIgG0YRoSgBs14MtMtqF3Uca2jbLiwffkA+0p6QVUBeXW2/xYO9f7Zq3T+qBl
#     H+zXFm1l99d1l95jiacryI8EPyhwr5SQlnsw5YxOrh1eHGxywZjiEMnzGKShh5Mi
#     BlW816zT3ipx6DSLb8kwdn1IVOkCAwEAAaMyMDAwDwYDVR0TAQH/BAUwAwEB/zAd
#     BgNVHQ4EFgQU4cMMJtHBu6fLT+h6ToAWznZyPi8wDQYJKoZIhvcNAQEFBQADggEB
#     AIQZALdkkEg1KPJvDeqjM/ZWCvnfFA2ugdGZV6/sAjbrDdocQz2GuRuRzKPZX23P
#     lyMjnLwtK+k5pvPiPzDIAIxFpncaYG+wVAuwlS5np9X0+MDX0Kv9xcc+ctm9y6Uj
#     QvLCEOVPgyE4EzEPG+kWIgjV7YfTSFD/ohXA3acgasH54mndlf52arOm0YUj+pXI
#     t8rFus/RU+7dTKJlTLkpZKv59V6KyBTUVpMBM+4KgczbZJS4gNBdyQDacsOsP7yO
#     Qiq8B15xW60OMk9aQWyYsdy2U0XdimYhzbYYRSKFOyV4XZD+LqaKKSR/MCatbjny
#     HXsAx6s75z30yLXbCOS+BQM=
#     -----END CERTIFICATE-----'),
# 'WiFiMACAddress': '6c:40:08:df:de:d1'
#   }

# validate pair
# success:
# {'Request': 'ValidatePair'}
# unsuccess: (invalid host id)
# {'Request': 'ValidatePair', 'Error': 'InvalidHostID'}

