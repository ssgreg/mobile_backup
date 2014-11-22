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


#
# UsbMuxMessageReceiver
#

class UsbMuxMessageReceiver(object):
  def __init__(self):
    self.reset()

  def recv(self, connection):
    if not self.header:
      if len(self.data) < UsbMuxHeader.SIZE:
        self.data += connection.recv(UsbMuxHeader.SIZE - len(self.data))
        if len(self.data) == UsbMuxHeader.SIZE:
          self.header = UsbMuxHeader()
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
# PlistMessageReceiver
#

class PlistMessageReceiver(object):
  def __init__(self):
    self.reset()

  def recv(self, connection):
    if not self.header:
      if len(self.data) < PlistHeader.SIZE:
        self.data += connection.recv(PlistHeader.SIZE - len(self.data))
        if len(self.data) == PlistHeader.SIZE:
          self.header = PlistHeader()
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
    self.__message_receiver = UsbMuxMessageReceiver()

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
    self.__message_receiver = PlistMessageReceiver()

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
# UsbMuxPlistSession
#

class UsbMuxPlistSession(object):
  TAG_NOTIFICATION = 0
  TAG_FIRST = 0x1000000

  def __init__(self, connection):
    logger().debug('Starting usbmux plist session...')
    self.__channel = UsbMuxPlistChannel(connection)
    self.__channel.on_incoming_plist = self.__on_incoming_plist
    self.on_notification = lambda plist_data: None
    self.callbacks = {}
    self.tag = self.TAG_FIRST

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
# PlistSession
#

class PlistSession(object):
  def __init__(self, connection):
    logger().debug('Starting plist session...')
    self.__channel = PlistChannel(connection)
    self.__channel.on_incoming_plist = self.__on_incoming_plist
    self.callback = None

  def send(self, plist_data, on_result):
    self.callback = on_result
    self.__channel.send(plist_data)

  def __on_incoming_plist(self, plist_data):
      self.callback(plist_data)
      self.callback = None



def connect():
  if (sys.platform == 'darwin'):
    logger().info('Using UNIX socket to connect to the usbmuxd...')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(r'/var/run/usbmuxd')
  else:
    logger().info('Connection to the apple service...')
    sock = socket.socket()
    sock.connect('127.0.0.1', 27015)
  return sock


def create_usbmux_plist(command):
  pl = dict(
    BundleID = 'org.acronis.usbmuxd',
    ClientVersionString = '1.0.0',
    MessageType = command,
    ProgName = 'Acronis Mobile Backup',
    kLibUSBMuxVersion = 1)
  return pl

def create_usbmux_plist_list_devices():
  return create_usbmux_plist('ListDevices')

def create_usbmux_plist_read_buid():
  return create_usbmux_plist('ReadBUID')

def create_usbmux_plist_listen():
  return create_usbmux_plist('Listen')

def create_usbmux_plist_connect(did, port):
  plist_data = create_usbmux_plist('Connect')
  plist_data['DeviceID'] = did
  plist_data['PortNumber'] = port
  return plist_data


def create_plist_query_type(client):
  return dict(
    Label = client,
    Request = 'QueryType'
    )

def print_device_info(device):
  print '\t', 'did:', device.DeviceID, '| sn:', device.Properties.SerialNumber, '| contype:', device.Properties.ConnectionType, '| pid: {0}'.format(device.Properties.ProductID) if 'ProductID' in device.Properties else ''


#
# TestGetDeviceList
#

class TestGetDeviceList(object):
  def __init__(self, io_service):
    self.connection = Connection(io_service, connect())
    self.internal_session = UsbMuxPlistSession(self.connection)
    logger().debug('Getting device list...')
    self.internal_session.send(create_usbmux_plist_list_devices(), self.on_devices)

  def on_devices(self, devices):
    print 'device list:'
    for i in devices.DeviceList:
      print_device_info(i)
    #
    logger().debug('Getting buid...')
    self.internal_session.send(create_usbmux_plist_read_buid(), self.on_buid)

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
    self.internal_session = UsbMuxPlistSession(self.connection)
    self.internal_session.on_notification = self.on_notification
    #
    logger().debug('Listening for devices...')
    self.internal_session.send(create_usbmux_plist_listen(), self.on_listen)

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
# TestConnectToLockdown
#

class TestConnectToLockdown(object):
  def __init__(self, io_service, did):
    self.did = did
    self.connection = Connection(io_service, connect())
    self.internal_session = UsbMuxPlistSession(self.connection)
    #
    logger().debug('Connecting to lockdown...')
    self.internal_session.send(create_usbmux_plist_connect(did, 32498), self.on_connect_to_lockdown)

  def on_connect_to_lockdown(self, confirmation):
    if confirmation.Number != 0:
      print "Failed to connect to the lockdown service of the device with a did:", self.did
      self.close()
    else:
      self.internal_session = PlistSession(self.connection)
      logger().debug('Quering lockdown type...')
      self.internal_session.send(create_plist_query_type('idevicebackup2'), self.on_query_type)


  def on_query_type(self, result):
    self.close()

  def close(self):
    self.connection.close()


def Main():
  print "Acronis Mobile Backup for Apple devices."
  configure_logger()
  logger().info('Current platform: {0}'.format(sys.platform))

  io_service = IOService()
#  TestGetDeviceList(io_service)
#  TestListenForDevices(io_service)
  TestConnectToLockdown(io_service, 373)
  io_service.run()


Main()


# Devices that accessed only by network are not enumerates via listen session.
# It's impossible to send another request before we get response from the prev request (both for usbmux and plist). Like zmq request/reply socket.

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
# {'Number': 3, 'MessageType': 'Result'}
# to incorrect device id:
# {'Number': 2, 'MessageType': 'Result'}

