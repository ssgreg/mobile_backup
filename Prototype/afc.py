# -*- coding: utf-8 -*-
# 
# afc.py
# AppleFileCoduit service
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


import struct
#
from logger import *
from tools import *
import wl
import async


AFC_SERVICE_TYPE = 'com.apple.afc'

#
# Operation
#


class Operation:
  INVALID                   = 0x00000000  # Invalid
  STATUS                    = 0x00000001  # Status
  DATA                      = 0x00000002  # Data
  READ_DIR                  = 0x00000003  # ReadDir
  READ_FILE                 = 0x00000004  # ReadFile
  WRITE_FILE                = 0x00000005  # WriteFile
  WRITE_PART                = 0x00000006  # WritePart
  TRUNCATE                  = 0x00000007  # TruncateFile
  REMOVE_PATH               = 0x00000008  # RemovePath
  MAKE_DIR                  = 0x00000009  # MakeDir
  GET_FILE_INFO             = 0x0000000A  # GetFileInfo
  GET_DEVINFO               = 0x0000000B  # GetDeviceInfo
  WRITE_FILE_ATOM           = 0x0000000C  # WriteFileAtomic (tmp file+rename)
  FILE_OPEN                 = 0x0000000D  # FileRefOpen
  FILE_OPEN_RES             = 0x0000000E  # FileRefOpenResult
  FILE_READ                 = 0x0000000F  # FileRefRead
  FILE_WRITE                = 0x00000010  # FileRefWrite
  FILE_SEEK                 = 0x00000011  # FileRefSeek
  FILE_TELL                 = 0x00000012  # FileRefTell
  FILE_TELL_RES             = 0x00000013  # FileRefTellResult
  FILE_CLOSE                = 0x00000014  # FileRefClose
  FILE_SET_SIZE             = 0x00000015  # FileRefSetFileSize (ftruncate)
  GET_CON_INFO              = 0x00000016  # GetConnectionInfo
  SET_CON_OPTIONS           = 0x00000017  # SetConnectionOptions
  RENAME_PATH               = 0x00000018  # RenamePath
  SET_FS_BS                 = 0x00000019  # SetFSBlockSize (0x800000)
  SET_SOCKET_BS             = 0x0000001A  # SetSocketBlockSize (0x800000)
  FILE_LOCK                 = 0x0000001B  # FileRefLock
  MAKE_LINK                 = 0x0000001C  # MakeLink
  GET_FILE_HASH             = 0x0000001D  # GetFileHash
  SET_FILE_MOD_TIME         = 0x0000001E  # SetModTime
  GET_FILE_HASH_RANGE       = 0x0000001F  # GetFileHashWithRange
  # iOS 6
  FILE_SET_IMMUTABLE_HINT   = 0x00000020  # FileRefSetImmutableHint
  GET_SZE_OF_PATH_CONTENTS  = 0x00000021  # GetSizeOfPathContents
  REMOV_PATH_AND_CONTENTS   = 0x00000022  # RemovePathAndContents
  DIR_OPEN                  = 0x00000023  # DirectoryEnumeratorRefOpen
  DIR_OPEN_RESULT           = 0x00000024  # DirectoryEnumeratorRefOpenResult
  DIR_READ                  = 0x00000025  # DirectoryEnumeratorRefRead
  DIR_CLOSE                 = 0x00000026  # DirectoryEnumeratorRefClose
  # iOS 7
  FILE_READ_OFFSET          = 0x00000027  # FileRefReadWithOffset
  FILE_WRITE_OFFSET         = 0x00000028  # FileRefWriteWithOffset


class OperationResult:
  SUCCESS               =  0
  UNKNOWN_ERROR         =  1
  OP_HEADER_INVALID     =  2
  NO_RESOURCES          =  3
  READ_ERROR            =  4
  WRITE_ERROR           =  5
  UNKNOWN_PACKET_TYPE   =  6
  INVALID_ARG           =  7
  OBJECT_NOT_FOUND      =  8
  OBJECT_IS_DIR         =  9
  PERM_DENIED           = 10
  SERVICE_NOT_CONNECTED = 11
  OP_TIMEOUT            = 12
  TOO_MUCH_DATA         = 13
  END_OF_DATA           = 14
  OP_NOT_SUPPORTED      = 15
  OBJECT_EXISTS         = 16
  OBJECT_BUSY           = 17
  NO_SPACE_LEFT         = 18
  OP_WOULD_BLOCK        = 19
  IO_ERROR              = 20
  OP_INTERRUPTED        = 21
  OP_IN_PROGRESS        = 22
  INTERNAL_ERROR        = 23
  MUX_ERROR             = 30
  NO_MEM                = 31
  NOT_ENOUGH_DATA       = 32
  DIR_NOT_EMPTY         = 33
  FORCE_SIGNED_TYPE     = -1


#
# OpenFileWLink
#

class OpenFileWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.afc.open_file(self.data.path, self.data.mode, lambda x: self.blocked() or self.on_open_file(x))
    self.stop_next()

  def on_open_file(self, handle):
    self.data.handle = handle
    self.next()


#
# LockFileWLink
#

class LockFileWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.afc.lock_file(self.data.lock_operation, lambda x: self.blocked() or self.on_lock_file(x))
    self.stop_next()

  def on_lock_file(self, lock_result):
    self.data.lock_result = lock_result
    self.next()


#
# GetFileInfoWLink
#

class GetFileInfoWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.afc.get_file_info(lambda x: self.blocked() or self.on_get_file_info())
    self.stop_next()

  def on_get_file_info(self):
    self.next()


#
# CloseFileWLink
#

class CloseFileWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.afc.close_file(lambda: self.blocked() or self.on_close_file())
    self.stop_next()

  def on_close_file(self):
    self.next()


#
# Service
#

class Service:
  def __init__(self, connection):
    self.data = dict(connection=connection)
    #
    self.workflow = wl.WorkflowBatch(
      InternalChangeSessionToAfcWLink(self.data),
    )
    self.workflow.start()

  def open_file(self, path, mode, on_result):
    self.workflow = wl.WorkflowBatch(
      InternalOpenFileWLink(self.data, path=path, mode=mode),
      wl.ProxyWorkflowLink(lambda: on_result(self.data['handle']))
    )
    self.workflow.start()

  def lock_file(self, lock_operation, on_result):
    self.workflow = wl.WorkflowBatch(
      InternalLockFileWLink(self.data, lock_operation=lock_operation),
      wl.ProxyWorkflowLink(lambda: on_result(self.data['lock_result']))
    )
    self.workflow.start()

  def close_file(self, on_result):
    self.workflow = wl.WorkflowBatch(
      InternalCloseFileWLink(self.data),
      wl.ProxyWorkflowLink(on_result),
    )
    self.workflow.start()

  def close(self):
    logger().debug('Closing AFC connection...')
    self.data['connection'].close()


#
# InternalChangeSessionToAfcWLink
#

class InternalChangeSessionToAfcWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.session = Session(self.data.connection)
    self.next()


#
# InternalOpenFileWLink
#

class InternalOpenFileWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('InternalOpenFileWLink: Opening file {0}'.format(self.data.path))
    self.data.session.send(Operation.FILE_OPEN, FileNameAndModePacket(self.data.path, self.data.mode).encode(), None, lambda x, y, z: self.blocked() or self.on_open_file(x, y, z))
    self.stop_next()

  def on_open_file(self, operation, data, payload):
    if operation == Operation.FILE_OPEN_RES:
      self.data.handle = ResultPacket.decode(data).param
      logger().debug('InternalOpenFileWLink: Done. File handle: {0}'.format(self.data.handle))
      self.next()
    else:
      raise RuntimeError('Failed to open file {0}'.format(self.data.path))


#
# InternalLockFileWLink
#

class InternalLockFileWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('InternalLockFileWLink: Locking file handle {0} with op {1}'.format(self.data.handle, self.data.lock_operation))
    self.data.session.send(Operation.FILE_LOCK, LockInfoPacket(self.data.handle, self.data.lock_operation).encode(), None, lambda x, y, z: self.blocked() or self.on_lock_file(x, y, z))
    self.stop_next()

  def on_lock_file(self, operation, data, payload):
    if operation == Operation.STATUS:
      self.data.lock_result = ResultPacket.decode(data).param
      logger().debug('InternalLockFileWLink: Done. Result: {0}'.format(self.data.lock_result))
      self.next()
    else:
      raise RuntimeError('Failed to lock file with handle {0}'.format(self.data.handle))


#
# InternalCloseFileWLink
#

class InternalCloseFileWLink(wl.WorkflowLink):
  def proceed(self):
    logger().debug('InternalCloseFileWLink: Closing file handle {0}'.format(self.data.handle))
    self.data.session.send(Operation.FILE_CLOSE, HandlePacket(self.data.handle).encode(), None, lambda x, y, z: self.blocked() or self.on_close_file(x, y, z))
    self.stop_next()

  def on_close_file(self, operation, data, payload):
    if operation == Operation.STATUS:
      self.data.handle = None
      self.data.close_result = ResultPacket.decode(data).param
      logger().debug('InternalCloseFileWLink: Done.')
      self.next()
    else:
      raise RuntimeError('Failed to close file with handle {0}'.format(self.data.handle))


#
# Session
#

class Session:
  def __init__(self, connection):
    self.__channel = PacketChannel(connection)
    self.__channel.on_incoming_packet = self.on_incoming_packet
    self.callbacks = {}
    self.index = 0
    logger().debug('Afc session has started.')

  def send(self, operation, data, payload, on_result):
    self.callbacks[self.index] = on_result
    self.__channel.send(operation, data, payload, self.index)
    self.index += 1

  def on_incoming_packet(self, operation, data, payload, index):
    self.callbacks[index](operation, data, payload)
    del self.callbacks[index]


#
# MessageReceiver
#

class MessageReceiver:
  def __init__(self):
    self.reset()

  def recv(self, connection):
    if not self.header:
      if len(self.__data) < Header.SIZE:
        self.__data += connection.recv(Header.SIZE - len(self.__data))
        if len(self.__data) == Header.SIZE:
          self.header = Header.decode(self.__data)
          self.__data = b''
          if self.header.size == 0 and self.header.payload_size == 0:
            return True
    elif self.header.size > 0:
      if len(self.__data) < self.header.size:
        self.__data += connection.recv(self.header.size - len(self.__data))
        if len(self.__data) == self.header.size:
          self.data = self.__data
          self.__data = b''
          if self.header.payload_size == 0:
            return True
    elif self.header.payload_size > 0:
      if len(self.__data) < self.header.size:
        self.__data += connection.recv(self.header.payload_size - len(self.__data))
        if len(self.__data) == self.header.size:
          self.payload = self.__data
          self.__data = b''
          return True
    return False

  def reset(self):
    self.header = None
    self.data = b''
    self.payload = b''
    self.__data = b''


#
# PacketChannel
#

class PacketChannel:
  def __init__(self, connection):
    self.connection = connection
    self.connection.on_ready_to_recv = self.__on_ready_to_recv
    self.on_incoming_packet = lambda data, tag, mtype: None
    self.__message_receiver = MessageReceiver()

  def send(self, operation, data, payload, index):
    header = Header(len(data) if data else 0, len(payload) if payload else 0, index, operation)
    self.connection.send(header.encode())
    if data:
      self.connection.send(data)
    if payload:
      self.connection.send(payload)

  def __on_ready_to_recv(self):
    if self.__message_receiver.recv(self.connection):
      header = self.__message_receiver.header
      data = self.__message_receiver.data
      payload = self.__message_receiver.payload
      self.__message_receiver.reset()
      if header.magic != header.MAGIC:
        raise RuntimeError('Incorrect packet header.')
      self.on_incoming_packet(header.operation, data, payload, header.index)


#
# Header
#

class Header:
  SIZE = 40
  MAGIC = b'CFA6LPAA'

  def __init__(self, size=None, payload_size=None, index=None, operation=None):
    self.magic = self.MAGIC
    self.size = size
    self.payload_size = payload_size
    self.index = index
    self.operation = operation

  def encode(self):
    return struct.pack('<8sQQQQ', self.magic, self.size  + self.SIZE, self.size + self.SIZE + self.payload_size, self.index, self.operation)

  @classmethod
  def decode(self, encoded):
    magic, size, payload_size, index, operation = struct.unpack_from('<8sQQQQ', encoded)
    payload_size -= size
    size -= self.SIZE
    return Header(size, payload_size, index, operation)


#
# FileModeWithNamePacket
#

class FileNameAndModePacket:
  def __init__(self, name=None, mode=None):
    self.name = name
    self.mode = mode

  def encode(self):
    name = str.encode(self.name + '\0')
    return struct.pack('<Q{0}s'.format(len(name)), self.mode, name)

  # def decode(self, encoded):
  #   self.mode, self.name = struct.unpack_from('<Q{0}s'.format(len(encoded) - 8 - 1), encoded)
  #   self.name = self.name.decode('ascii')


#
# LockInfoPacket
#

class LockInfoPacket:
  def __init__(self, handle=None, lock_operation=None):
    self.handle = handle
    self.lock_operation = lock_operation

  def encode(self):
    return struct.pack('<QQ', self.handle, self.lock_operation)

  # def decode(self, encoded):
  #   self.handle, self.lock_operation = struct.unpack_from('<QQ', encoded)


#
# HandlePacket
#

class HandlePacket:
  def __init__(self, handle=None):
    self.handle = handle

  def encode(self):
    return struct.pack('<Q', self.handle)

  # def decode(self, encoded):
  #   self.handle,  = struct.unpack_from('<Q', encoded)


#
# ResultPacket
#

class ResultPacket:
  def __init__(self, param=None):
    self.param = param

  def encode(self):
    return struct.pack('<Q', self.param)

  @classmethod
  def decode(self, encoded):
    param,  = struct.unpack_from('<Q', encoded)
    return ResultPacket(param)


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
        client = Client(channel_factory)
        app_log.debug('Making a afc.Client...', **log_extra(client))
        yield client._connect()
        app_log.info('An afc.Client object is created', **log_extra(client))
        return client

    @async.coroutine
    def start_service(name):
        return None

    def close(self):
        self._temp.close()
#        yield self._session.stop()

    @async.coroutine
    def _connect(self):
        self._temp = yield self._channel_factory(AFC_SERVICE_TYPE)
#        yield self._session.start()
#        self._buid = yield self._read_buid()
        return self
