import socket
import plist
import struct
import binascii
import sched
import select
import time
import collections


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
#    print('CON[{}] <-- ({}) {}'.format(id(self.io), len(data), binascii.hexlify(data)))
    self.__io.send(data)

  def recv(self, size):
    # data = b''
    # while len(data) < size:
    #   data += self.__io.recv(size - len(data))
#    print('CON[{}] --> ({}) {}'.format(id(self.io), len(data), binascii.hexlify(data)))
    data = self.__io.recv(size)
    if not data:
      raise RuntimeError('Connection forcibly closed.')
    return data

  def __on_ready_to_recv(self):
    self.on_ready_to_recv()



#class UsbMuxdPlistMessageChannel



class UsbMuxdListenSession(object):
  def __init__(self, connection):
    self.connection = connection
    self.tag = 0


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


class UsbMuxPlistSession(object):
  TAG_NOTIFICATION = 0
  TAG_FIRST = 0x1000000

  def __init__(self, connection):
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
    pass



class UsbMuxdListSession(object):
  def __init__(self, connection):
    self.internal_session = UsbMuxPlistSession(connection)

  def devices(self, on_result):
    self.internal_session.send(create_plist_list_device(), on_result)



def connect():
  sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  sock.connect(r'/var/run/usbmuxd')
  return sock


def create_plist(command):
  pl = dict(
    BundleID = 'org.acronis.usbmuxd',
    ClientVersionString = '1.0.0',
    MessageType = command,
    ProgName = 'Acronis Mobile Backup',
    kLibUSBMuxVersion = 1)
  return pl


def create_plist_list_device():
  return create_plist('ListDevices')

#
# TestGetDeviceList
#

class TestGetDeviceList(object):
  def __init__(self, io_service):
    #
    self.connection = Connection(io_service, connect())
    self.list_session = UsbMuxdListSession(self.connection)
    self.list_session.devices(self.on_devices)

  def on_devices(self, devices):
    for i in devices.DeviceList:
      print "sn:", i.Properties.SerialNumber, "| did:", i.DeviceID, "| contype:", i.Properties.ConnectionType
    self.close()

  def close(self):
    self.connection.close()



io_service = IOService()
TestGetDeviceList(io_service)
io_service.run()



# io_service.scheduler.enter(0, 1, lambda io_service: TestGetDeviceList(io_service) , (io_service, ) )
# io_service.scheduler.enter(0, 1, lambda io_service: TestGetDeviceList(io_service) , (io_service, ) )

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

