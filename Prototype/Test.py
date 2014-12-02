import socket
import plistlib
import struct
import binascii
import sched
import select
import time
import collections
import os
import sys
import ssl
import logging
import logging.config
import tempfile
import argparse
#
import wl


def configure_logger():
  logging.config.fileConfig('logging.ini')

def logger():
  return logging.getLogger(__name__)


#
# IOService
#

class IOService:
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
      if self.has_io():
        self.__process_io()
      else:
        break

  def stopped(self):
    return self.stop_flag

  def has_io(self):
    return len(self.__rxh.ios) != 0

  def __process_io(self, timeout=None):
    if self.has_io():
      rios, tios, xios = select.select(self.__rxh.ios, self.__txh.ios, self.__xxh.ios, timeout)
      for xh, signaled_ios in ((self.__rxh, rios), (self.__txh, tios), (self.__xxh, xios)):
        for io in signaled_ios:
          xh.x[io]()
    else:
      time.sleep(timeout)


#
# Connection
#

class Connection:
  def __init__(self, service, io):
    self.__io = io
    self.__service = service
    self.__service.register(io, self.__on_ready_to_recv)
    self.on_ready_to_recv = lambda: None

  def close(self):
    self.__service.unregister(self.__io)
    self.__io.close()

  def send(self, data):
#    print('CON[{}] <-- ({}) {}'.format(id(self.__io), len(data), binascii.hexlify(data)))
    self.__io.send(data)

  def recv(self, size):
    data = self.__io.recv(size)
#    print('CON[{}] --> ({}) {}'.format(id(self.__io), len(data), binascii.hexlify(data)))
    if not data:
      raise RuntimeError('Connection forcibly closed.')
    return data

  def enable_ssl(self, cert=None, key=None):
    logger().debug('SSL has been enabled.')
    cert_file = tempfile.NamedTemporaryFile(delete=False) if cert else None
    key_file = tempfile.NamedTemporaryFile(delete=False) if key else None
    try:
      if cert:
        cert_file.write(cert)
        cert_file.close()
        cert_file = cert_file.name
      if key:
        key_file.write(key)
        key_file.close()
        key_file = key_file.name
      self.__service.unregister(self.__io)
      self.__io = ssl.wrap_socket(self.__io, certfile=cert_file, keyfile=key_file, ssl_version=3)
      self.__service.register(self.__io, self.__on_ready_to_recv)
    finally:
      if cert:
        os.remove(cert_file)
      if key:
        os.remove(key_file)

  def __on_ready_to_recv(self):
    self.on_ready_to_recv()


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
# MessageReceiver
#

class MessageReceiver:
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
  plist_data['PortNumber'] = socket.htons(port)
  return plist_data

def create_usbmux_message_read_pair_record(sn):
  plist_data = create_usbmux_message('ReadPairRecord')
  plist_data['PairRecordID'] = sn
  return plist_data

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
    self.connection = Connection(io_service, connect())
    self.internal_session = UsbMuxSession(self.connection)
    logger().debug('Getting device list...')
    self.internal_session.send(create_usbmux_message_list_devices(), self.on_devices)

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
    self.connection = Connection(io_service, connect())
    self.internal_session = UsbMuxSession(self.connection)
    self.internal_session.on_notification = self.on_notification
    #
    logger().debug('Listening for devices...')
    self.internal_session.send(create_usbmux_message_listen(), self.on_listen)

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
    self.data['connection'] = Connection(self.data['io_service'], connect())
    self.data['session'] = UsbMuxSession(self.data['connection'])
    self.next()


#
# ReadPairRecordWLink
#

class ReadPairRecordWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Reading pair record of a device with a sn = {0}'.format(self.data['sn']))
    self.data['session'].send(create_usbmux_message_read_pair_record(self.data['sn']), self.on_get_pair_record)
  
  def on_get_pair_record(self, result):
    if 'PairRecordData' not in result:
      print('Invalid pair record result.')
      self.stop_next()
    else:
      self.data['pair_record_data'] = plistlib.loads(result['PairRecordData'])
      logger().debug('Done. HostID = {0}'.format(self.data['pair_record_data']['HostID']))
      self.next();


#
# ReadBuidWLink
#

class ReadBuidWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Reading BUID')
    self.data['session'].send(create_usbmux_message_read_buid(), self.on_read_buid)
  
  def on_read_buid(self, result):
    if 'BUID' not in result:
      print('Invalid BUID result.')
      self.stop_next()
    else:
      self.data['BUID'] = result['BUID']
      logger().debug('Done. BUID = {0}'.format(self.data['BUID']))
      self.next();


#
# ConnectToServiceWLink
#

class ConnectToServiceWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Connecting to a service, did = {0} port = {1}'.format(self.data['did'], self.data['service_port']))
    self.data['session'].send(create_usbmux_message_connect(self.data['did'], self.data['service_port']), self.on_connect_to_lockdown)

  def on_connect_to_lockdown(self, confirmation):
    if confirmation['Number'] != 0:
      print('Failed to connect with an error =', confirmation['Number'])
      self.stop_next()
    else:
      logger().debug('Done')
      self.data['session'] = LockdownSession(self.data['connection'])
      self.next();


#
# LockdownServiceCheckTypeWLink
#

class LockdownServiceCheckTypeWLink(wl.WorkflowLink):
  LOCKDOWN_SERVICE_TYPE = 'com.apple.mobile.lockdown'

  def proceed(self):
    logger().debug('Checking lockdown service type...')
    self.data['session'].send(create_lockdown_message_query_type(), self.on_check_lockdown_type)

  def on_check_lockdown_type(self, result):
    if 'Type' not in result or result['Type'] != self.LOCKDOWN_SERVICE_TYPE:
      print('Failed to query the lockdown service type. Answer:', result)
      self.stop_next()
    else:
      logger().debug('Done. Service type is: {0}'.format(result['Type']))
      self.next();


#
# ValidatePairRecordWLink
#

class ValidatePairRecordWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Validating pair record with HostID = {0}'.format(self.data['pair_record_data']['HostID']))
    self.data['session'].send(create_lockdown_message_validate_pair(self.data['pair_record_data']['HostID']), self.on_validate_pair_record)

  def on_validate_pair_record(self, result):
    if 'Error' in result:
      print('Failed to validate pair. Error:', result['Error'])
      self.stop_next()
    else:
      logger().debug('Done.')
      self.next();


#
# LockdownStartSessionWLink
#

class LockdownStartSessionWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Starting lockdown session with HostID = {0} and BUID = {1}'.format(self.data['pair_record_data']['HostID'], self.data['BUID']))
    self.data['session'].send(create_lockdown_message_start_session(self.data['pair_record_data']['HostID'], self.data['BUID']), self.on_start_session)

  def on_start_session(self, result):
    if 'Error' in result:
      print('Failed to start session. Error:', result['Error'])
      self.stop_next()
    else:
      session_id = result['SessionID']
      use_ssl = result['EnableSessionSSL']
      logger().debug('Done. SessionID = {0}, UseSSL = {1}'.format(session_id, use_ssl))
      if use_ssl:
        self.data['session'].enable_ssl(self.data['pair_record_data']['HostCertificate'], self.data['pair_record_data']['HostPrivateKey'])
      self.next();


#
# LockdownStartServiceWLink
#

class LockdownStartServiceWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('Starting {0} via Lockdown {1} escrow bag'.format(self.data['service_name'], "with" if self.data['use_escrow_bag'] else "without"))
    escrow_bag = self.data['pair_record_data']['EscrowBag'] if self.data['use_escrow_bag'] else None
    self.data['session'].send(create_lockdown_message_start_service(self.data['service_name'], escrow_bag), self.on_start_service)

  def on_start_service(self, result):
    if 'Error' in result:
      print('Failed to start service. Error:', result['Error'])
      if result['Error'] == 'EscrowLocked':
        print('It''s impossible to back up the device because it is locked with a passcode. You must enter a passcode on the device before it can be backed up.')
      self.stop_next()
    else:
      logger().debug('Done. Port = {0}'.format(result['Port']))
      self.data['port'] = result['Port']
      self.next();


#
# LambdaWLink
#

class LambdaWLink(wl.WorkflowLink):
  def __init__(self, on_perform, on_block=None):
    super(LambdaWLink, self).__init__()
    self.on_perform = on_perform
    self.on_block = on_block

  def block(self):
    if self.on_block:
      self.on_block()

  def proceed(self):
    if self.on_perform():
      self.next()


#
# LockdownService
#

class LockdownService:
  LOCKDOWN_SERVICE_PORT = 62078

  def __init__(self, io_service, did, sn):
    self.io_service = io_service
    self.did = did
    self.sn = sn
    self.connection = None

  def start_another_service(self, name, on_result):
    self.__start_another_service(name, False, on_result)

  def start_another_service_with_escrow_bag(self, name, on_result):
    self.__start_another_service(name, True, on_result)

  def __start_another_service(self, name, use_escrow_bag, on_result):
    data = dict(io_service=self.io_service, service_name=name, did=self.did, sn=self.sn)
    logger().debug('Starting service ''{0}'' with did = {1} and sn = {2}'.format(name, self.did, self.sn))
    #
    workflow = wl.link(
      ConnectToUsbMuxdWLink(data),
      ReadBuidWLink(data),
      ReadPairRecordWLink(data),
      ConnectToServiceWLink(data, service_port=self.LOCKDOWN_SERVICE_PORT),
      LockdownServiceCheckTypeWLink(data),
      ValidatePairRecordWLink(data),
      LockdownStartSessionWLink(data),
      LockdownStartServiceWLink(data, use_escrow_bag=use_escrow_bag),
      LambdaWLink(lambda: self.__call_on_result_for_start_another_service(on_result, data)))
    workflow.start()



  def __call_on_result_for_start_another_service(self, on_result, data):
    self.connection = data['connection']
    logger().debug('Service {0} has been started on port = {1}'.format(data['service_name'], data['port']))
    on_result(data['port'])

  def close(self):
    logger().debug('Closing connection...')
    self.connection.close()


#
# StartServiceViaLockdown
#

class StartServiceViaLockdownWLink(wl.WorkflowLink):
  def proceed(self):
    if self.data['use_escrow_bag']:
      self.data['lockdown'].start_another_service_with_escrow_bag(self.data['service'], self.on_start_requested_service)
    else:
      self.data['lockdown'].start_another_service(self.data['service'], self.on_start_requested_service)

  def on_start_requested_service(self, port):
    self.data['service_port'] = port
    self.next()


#
# TestBackup
#

class TestBackup:
  MOBILEBACKUP2_SERVICE_NAME = 'com.apple.mobilebackup2'
  NP_SERVICE_NAME = 'com.apple.mobile.notification_proxy'

  def __init__(self, io_service, did, sn):
    data = dict(io_service=io_service, lockdown=LockdownService(io_service, did, sn), did=did, sn=sn)
    #
    workflow = wl.link(
      StartServiceViaLockdownWLink(data, service=self.MOBILEBACKUP2_SERVICE_NAME, use_escrow_bag=True),
      LambdaWLink(lambda: self.__close(data), lambda: self.__close(data)),
      ConnectToUsbMuxdWLink(data),
      ConnectToServiceWLink(data),
      LockdownServiceCheckTypeWLink(data, service_type=self.MOBILEBACKUP2_SERVICE_NAME),
      LambdaWLink(lambda: self.close(data), lambda: self.close(data)))
    workflow.start()

  def __close(self, data):
    if 'lockdown' in data:
      data['lockdown'].close()
    return True

  def close(self, data):
    logger().debug('Closing connection...')
    data['connection'].close()
    return True


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
  TestGetDeviceList(io_service)

def command_listen(args, io_service):
  TestListenForDevices(io_service, args.timeout)

def command_test(args, io_service):
  TestBackup(io_service, args.did, args.sn)


def Main():
  print("Acronis Mobile Backup prototype for Apple devices 1.0")
  configure_logger()
  logger().info('Current platform: {0}'.format(sys.platform))

  commands = {
    'list': command_list,
    'listen': command_listen,
    'test': command_test
  }
  args = configure_argparse().parse_args()

  io_service = IOService()
  commands[args.command](args, io_service)
  io_service.run()

Main()
