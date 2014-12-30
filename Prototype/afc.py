# -*- coding: utf-8 -*-
#
# afc.py
# AppleFileCoduit service
#
# Created by Grigory Zubankov.
# Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


import struct
import datetime
#
import async
from logger import app_log
from tools import log_extra


AFC_SERVICE_TYPE = 'com.apple.afc'


#
# Operation
#


class Operation:
    INVALID = 0x00000000  # Invalid
    STATUS = 0x00000001  # Status
    DATA = 0x00000002  # Data
    READ_DIR = 0x00000003  # ReadDir
    READ_FILE = 0x00000004  # ReadFile
    WRITE_FILE = 0x00000005  # WriteFile
    WRITE_PART = 0x00000006  # WritePart
    TRUNCATE = 0x00000007  # TruncateFile
    REMOVE_PATH = 0x00000008  # RemovePath
    MAKE_DIR = 0x00000009  # MakeDir
    GET_FILE_INFO = 0x0000000A  # GetFileInfo
    GET_DEVINFO = 0x0000000B  # GetDeviceInfo
    WRITE_FILE_ATOM = 0x0000000C  # WriteFileAtomic (tmp file+rename)
    FILE_OPEN = 0x0000000D  # FileRefOpen
    FILE_OPEN_RES = 0x0000000E  # FileRefOpenResult
    FILE_READ = 0x0000000F  # FileRefRead
    FILE_WRITE = 0x00000010  # FileRefWrite
    FILE_SEEK = 0x00000011  # FileRefSeek
    FILE_TELL = 0x00000012  # FileRefTell
    FILE_TELL_RES = 0x00000013  # FileRefTellResult
    FILE_CLOSE = 0x00000014  # FileRefClose
    FILE_SET_SIZE = 0x00000015  # FileRefSetFileSize (ftruncate)
    GET_CON_INFO = 0x00000016  # GetConnectionInfo
    SET_CON_OPTIONS = 0x00000017  # SetConnectionOptions
    RENAME_PATH = 0x00000018  # RenamePath
    SET_FS_BS = 0x00000019  # SetFSBlockSize (0x800000)
    SET_SOCKET_BS = 0x0000001A  # SetSocketBlockSize (0x800000)
    FILE_LOCK = 0x0000001B  # FileRefLock
    MAKE_LINK = 0x0000001C  # MakeLink
    GET_FILE_HASH = 0x0000001D  # GetFileHash
    SET_FILE_MOD_TIME = 0x0000001E  # SetModTime
    GET_FILE_HASH_RANGE = 0x0000001F  # GetFileHashWithRange
    # iOS 6
    FILE_SET_IMMUTABLE_HINT = 0x00000020  # FileRefSetImmutableHint
    GET_SZE_OF_PATH_CONTENTS = 0x00000021  # GetSizeOfPathContents
    REMOVE_PATH_AND_CONTENTS = 0x00000022  # RemovePathAndContents
    DIR_OPEN = 0x00000023  # DirectoryEnumeratorRefOpen
    DIR_OPEN_RESULT = 0x00000024  # DirectoryEnumeratorRefOpenResult
    DIR_READ = 0x00000025  # DirectoryEnumeratorRefRead
    DIR_CLOSE = 0x00000026  # DirectoryEnumeratorRefClose
    # iOS 7
    FILE_READ_OFFSET = 0x00000027  # FileRefReadWithOffset
    FILE_WRITE_OFFSET = 0x00000028  # FileRefWriteWithOffset


class OperationResult:
    SUCCESS = 0
    UNKNOWN_ERROR = 1
    OP_HEADER_INVALID = 2
    NO_RESOURCES = 3
    READ_ERROR = 4
    WRITE_ERROR = 5
    UNKNOWN_PACKET_TYPE = 6
    INVALID_ARG = 7
    OBJECT_NOT_FOUND = 8
    OBJECT_IS_DIR = 9
    PERM_DENIED = 10
    SERVICE_NOT_CONNECTED = 11
    OP_TIMEOUT = 12
    TOO_MUCH_DATA = 13
    END_OF_DATA = 14
    OP_NOT_SUPPORTED = 15
    OBJECT_EXISTS = 16
    OBJECT_BUSY = 17
    NO_SPACE_LEFT = 18
    OP_WOULD_BLOCK = 19
    IO_ERROR = 20
    OP_INTERRUPTED = 21
    OP_IN_PROGRESS = 22
    INTERNAL_ERROR = 23
    MUX_ERROR = 30
    NO_MEM = 31
    NOT_ENOUGH_DATA = 32
    DIR_NOT_EMPTY = 33
    FORCE_SIGNED_TYPE = -1


class FileOpenMode:
    READ_ONLY = 0x00000001         # r   O_RDONLY
    READ_WRITE = 0x00000002        # r+  O_RDWR   | O_CREAT
    WRITE_ONLY = 0x00000003        # w   O_WRONLY | O_CREAT  | O_TRUNC
    WRITE_READ = 0x00000004        # w+  O_RDWR   | O_CREAT  | O_TRUNC
    WRITE_APPEND = 0x00000005      # a   O_WRONLY | O_APPEND | O_CREAT
    WRITE_READ_APPEND = 0x00000006  # a+  O_RDWR   | O_APPEND | O_CREAT


class FileLockMode:
    SHARED = 1 | 4
    EXCLUSIVE = 2 | 4
    UNLOCK = 8 | 4


#
# Header
#

class Header:
    SIZE = 40
    MAGIC = b'CFA6LPAA'

    def __init__(self, size=None, payload_size=None, index=None, operation=None):
        self.magic = self.MAGIC
        self.payload_size = payload_size
        self.size = size
        self.index = index
        self.operation = operation

    def encode(self):
        return struct.pack('<8sQQQQ', self.magic, self.size + self.SIZE + self.payload_size, self.size + self.SIZE,
                           self.index, self.operation)

    @classmethod
    def decode(self, encoded):
        magic, payload_size, size, index, operation = struct.unpack_from('<8sQQQQ', encoded)
        payload_size -= size
        size -= self.SIZE
        return Header(size, payload_size, index, operation)


def _pack(param1, param2=None):
    if param2:
        return struct.pack('<QQ', param1, param2)
    else:
        return struct.pack('<Q', param1)


def _pack_path_and_mode(path, mode):
    encoded = str.encode(path + '\0')
    return struct.pack('<Q{0}s'.format(len(encoded)), mode, encoded)


def _pack_path(path):
    encoded = str.encode(path + '\0')
    return struct.pack('<{0}s'.format(len(encoded)), encoded)


def _unpack_result(data):
    return struct.unpack_from('<Q', data)[0]


#
# InternalSession
#

class InternalSession:
    MAX_REPLY_SIZE = 1 * (1024 * 1024)  # 1 MB

    def __init__(self, channel_factory):
        self._channel_factory = channel_factory
        self._channel = None
        self._index = 0

    @async.coroutine
    def start(self):
        self._channel = yield self._channel_factory(AFC_SERVICE_TYPE)

    def stop(self):
        if self._channel:
            self._channel.close()

    @async.coroutine
    def fetch(self, op, data=None, payload=None):
        header = Header(len(data) if data else 0, len(payload) if payload else 0, self._index, op)
        header_data = header.encode()
        #
        self._channel.write(header_data)
        if data:
            self._channel.write(data)
        if payload:
            self._channel.write(payload)
        #
        self._index += 1
        return (yield self._read_message(header))

    def _validate_header(self, header, original_header):
        if header.index != original_header.index:
            raise RuntimeError('Damaged AFC header!')
        if header.size > self.MAX_REPLY_SIZE:
            raise RuntimeError('AFC data size is too big!')
        if header.payload_size > self.MAX_REPLY_SIZE:
            raise RuntimeError('AFC payload size is too big!')

    @async.coroutine
    def _read_message(self, original_header):
        header_data = yield self._channel.read_async(Header.SIZE)
        header = Header.decode(header_data)
        self._validate_header(header, original_header)
        data = None
        if header.size:
            data = yield self._channel.read_async(header.size)
        payload = None
        if header.payload_size:
            payload = yield self._channel.read_async(header.payload_size)
        return header.operation, data, payload

    def enable_ssl(self, cert, key):
        self._channel.enable_ssl(cert, key)


#
# Client
#

class Client:
    def __init__(self, channel_factory):
        self._channel_factory = channel_factory
        self._session = InternalSession(channel_factory)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    @staticmethod
    @async.coroutine
    def make(channel_factory):
        client = Client(channel_factory)
        yield client.connect()
        return client

    @async.coroutine
    def connect(self):
        app_log.debug('Connecting to an AFC service...', **log_extra(self))
        yield self._session.start()
        app_log.info('Connected to an AFC service...', **log_extra(self))
        return self

    def close(self):
        self._session.stop()

    @async.coroutine
    def open_file(self, path, mode):
        app_log.debug('Trying to open file \'{0}\' mode={1}'.format(path, mode), **log_extra(self))
        op, data, _ = yield self._session.fetch(Operation.FILE_OPEN, _pack_path_and_mode(path, mode))
        if op == Operation.FILE_OPEN_RES:
            handle = _unpack_result(data)
            app_log.info('Done. Handle={0}'.format(handle), **log_extra(self))
            return handle
        else:
            raise RuntimeError('Failed to open \'{0}\''.format(path))

    @async.coroutine
    def close_file(self, handle):
        app_log.debug('Trying to close file handle={0}'.format(handle), **log_extra(self))
        op, data, _ = yield self._session.fetch(Operation.FILE_CLOSE, _pack(handle))
        if op == Operation.STATUS:
            result = _unpack_result(data)
            app_log.info('Done. Handle={0}'.format(handle), **log_extra(self))
            return result
        else:
            raise RuntimeError('Failed to close file handle \'{0}\''.format(handle))

    @async.coroutine
    def lock_file(self, handle, mode):
        app_log.debug('Trying to lock file handle={0} with mode={1}'.format(handle, mode), **log_extra(self))
        op, data, _ = yield self._session.fetch(Operation.FILE_LOCK, _pack(handle, mode))
        if op == Operation.STATUS:
            result = _unpack_result(data)
            app_log.info('Done. Handle={0}'.format(handle), **log_extra(self))
            return result
        else:
            raise RuntimeError('Failed to close file handle \'{0}\''.format(handle))

    @async.coroutine
    def read_file(self, handle, length):
        app_log.debug('Trying to read file handle={0} with length={1}'.format(handle, length), **log_extra(self))
        op, _, payload = yield self._session.fetch(Operation.FILE_READ, _pack(handle, length))
        if op == Operation.DATA:
            if not payload:
                payload = b''
            app_log.info('Done. Received={0} bytes'.format(len(payload)), **log_extra(self))
            return payload
        else:
            raise RuntimeError('Failed to close file handle \'{0}\''.format(handle))

    @async.coroutine
    def file_info(self, path):
        app_log.debug('Getting info about \'{0}\'...'.format(path), **log_extra(self))
        op, _, payload = yield self._session.fetch(Operation.GET_FILE_INFO, _pack_path(path))
        if op == Operation.DATA:
            info = self._loads_file_info(payload)
            app_log.info('Done. {0} bytes, {1}'.format(info['st_size'], datetime.datetime.fromtimestamp(info['st_mtime'])),  **log_extra(self))
            return info
        else:
            raise RuntimeError('Failed to close file handle \'{0}\''.format(handle))

    def _loads_file_info(self, data):
        i = iter(data[:-1].split(b'\x00'))
        raw = dict(zip(i, i))
        result = {}
        if b'st_size' in raw:
            result['st_size'] = int(raw[b'st_size'])
        if b'st_nlink' in raw:
            result['st_nlink'] = int(raw[b'st_nlink'])
        if b'st_blocks' in raw:
            result['st_blocks'] = int(raw[b'st_blocks'])
        if b'st_ifmt' in raw:
            result['st_ifmt'] = raw[b'st_ifmt'].decode('ascii')
        if b'st_birthtime' in raw:
            # from nanosecods to seconds
            result['st_birthtime'] = float(raw[b'st_birthtime']) / 1e9
        if b'st_mtime' in raw:
            # from nanosecods to seconds
            result['st_mtime'] = float(raw[b'st_mtime']) / 1e9
        return result
