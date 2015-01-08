# -*- coding: utf-8 -*-
#
# mb2.py
# mobile_backup2 service
#
# Created by Grigory Zubankov.
# Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import struct
import plistlib
import os
import stat
import os.path
import datetime
#
import async
import device_link
from logger import app_log
from tools import log_extra, sizeof_fmt


MB2_SERVICE_TYPE = 'com.apple.mobilebackup2'


def create_message(request):
    return dict(
        MessageName=request
    )


def create_message_hello(versions):
    msg = create_message('Hello')
    msg.update(
        SupportedProtocolVersions=versions
    )
    return msg


def create_message_backup(target_sn, source_sn, force_full_backup=True):
    msg = create_message('Backup')
    msg.update(
        TargetIdentifier=target_sn,
        SourceIdentifier=source_sn,
        Options=dict(
            ForceFullBackup=force_full_backup
        )
    )
    return msg


def _pack_string(path):
    encoded = str.encode(path)
    return struct.pack('>I{0}s'.format(len(encoded)), len(encoded), encoded)


#
# InternalSession
#

class InternalSession:
    MAX_REPLY_SIZE = 1 * (1024 * 1024)  # 1 MB

    def __init__(self, channel_factory):
        self._channel_factory = channel_factory
        self._channel = None

    @async.coroutine
    def start(self):
        self._channel = yield self._channel_factory(service=MB2_SERVICE_TYPE, use_escrow_bag=True)

    def stop(self):
        self._channel.close()

    def send_raw(self, bytes):
        self._channel.write(bytes)

    def send(self, msg):
        print(msg)
        data = plistlib.dumps(msg, fmt=plistlib.FMT_BINARY)
        header_data = device_link.Header(len(data)).encode()
        #
        self._channel.write(header_data)
        self._channel.write(data)

    @async.coroutine
    def receive(self):
        header_data = yield self._channel.read_async(device_link.Header.SIZE)
        header = device_link.Header.decode(header_data)
        self._validate_header(header)
        data = yield self._channel.read_async(header.size)
        message = plistlib.loads(data, fmt=plistlib.FMT_BINARY)
        return message

    @async.coroutine
    def fetch(self, msg=None):
        if msg:
            self.send(msg)
        return (yield self.receive())

    def _validate_header(self, header):
        if header.size > self.MAX_REPLY_SIZE:
            raise RuntimeError('Lockdown header size is too big!')

    def enable_ssl(self, cert, key):
        self._channel.enable_ssl(cert, key)


#
# Client
#

class Client:
    def __init__(self, channel_factory):
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
        app_log.debug('Connecting to an mb2 service...', **log_extra(self))
        yield self._session.start()
        try:
            yield self._device_link_version_exchange()
            yield self._hello()
        except Exception as e:
            self._session.stop()
            raise e
        app_log.info('Connected to an mb2 service. Handshake is finished.', **log_extra(self))

    def close(self):
        self._session.stop()
        app_log.info('Closed', **log_extra(self))

    def request_backup(self, target_sn, source_sn, force_full_backup=True):
        app_log.debug('Requesting backup with options: force_full_backup={0}...'.format(force_full_backup), **log_extra(self))
        self._device_link_send_process_message(create_message_backup(target_sn, source_sn, force_full_backup))

    def send_files(self, folder, files):
        for file in files:
            error = self._send_file(folder, file)
            if error:
                break
        #
        self._session.send_raw(struct.pack('>I', 0))
        if error:
            self._device_link_send_status_response(-13, 'Multi status', error)
        else:
            self._device_link_send_status_response()

    def send_directory_contents(self, folder, directory):
        app_log.debug('Sending contents of dir \'{0}\' back to service...'.format(directory), **log_extra(self))
        content = {}
        count = 0
        root = os.path.join(folder, directory)
        for element in os.listdir(root):
            count += 1
            description = {}
            st = os.stat(os.path.join(root, element))
            # file type
            if stat.S_ISREG(st.st_mode):
                description['DLFileType'] = 'DLFileTypeRegular'
            elif stat.S_ISDIR(st.st_mode):
                description['DLFileType'] = 'DLFileTypeDirectory'
            else:
                description['DLFileType'] = 'DLFileTypeUnknown'
            # file size
            description['DLFileSize'] = st.st_size
            # file data
            description['DLFileModificationDate'] = datetime.datetime.fromtimestamp(st.st_mtime)
            #
            content[element] = description
        self._device_link_send_status_response(status2=content)
        app_log.info('Content of dir \'{0}\' is sent back to service. {1} elements was found'.format(directory, count), **log_extra(self))

    def send_free_disk_space(self, folder):
        app_log.debug('Sending free disk space...', **log_extra(self))
        # getting free space available for the current user
        statvfs = os.statvfs(folder)
        free_space = statvfs.f_frsize * statvfs.f_bavail
        #
        self._device_link_send_status_response(status2=free_space)
        app_log.info('Sent free disk space: {0}'.format(sizeof_fmt(free_space)), **log_extra(self))

    def send_create_directory(self, folder, directory):
        app_log.debug('Trying to create directory \'{0}\'...'.format(directory), **log_extra(self))
        try:
            os.makedirs(os.path.join(folder, directory), exist_ok=True)
        except OSError as e:
            self._device_link_send_status_response(code=-e.errno, status1=e.strerror)
            app_log.info('Failed to create directory \'{0}\'.'.format(directory), **log_extra(self))
        else:
            self._device_link_send_status_response()
            app_log.info('Directory \'{0}\' is created.'.format(directory), **log_extra(self))

    def _send_file(self, folder, file):
        app_log.debug('Sending file \'{0}\' back to service...'.format(file), **log_extra(self))
        self._session.send_raw(_pack_string(file))
        if os.path.isfile(os.path.join(folder, file)):
            app_log.info('File \'{0}\' is sent back to service'.format(file), **log_extra(self))
            return None
        else:
            self._session.send_raw(_pack_string('File not found'))
            result = {}
            result[file] = dict(DLFileErrorString='File not found', DLFileErrorCode=-6)
            app_log.info('File \'{0}\' not found'.format(file), **log_extra(self))
            return result

    @async.coroutine
    def receive_message(self):
        return (yield self._session.receive())

    @async.coroutine
    def _hello(self):
        versions = [2.0, 2.1]
        app_log.debug('Sending \'hello\' message. Supported protocol versions are: {0}...'.format(versions), **log_extra(self))
        reply = yield self._device_link_fetch_process_message(create_message_hello(versions))
        if len(reply) < 2 or reply[0] != 'DLMessageProcessMessage':
            raise RuntimeError('Failed to process message via device link. Bad reply: {0}'.format(reply))
        reply = reply[1]
        #
        if 'MessageName' not in reply or reply['MessageName'] != 'Response':
            raise RuntimeError('Failed to handle \'hello\' message. Bad reply: {0}'.format(reply))
        app_log.info('Device protocol version is: {0}'.format(reply['ProtocolVersion']))
        if reply['ErrorCode'] != 0:
            raise RuntimeError('Failed to handle \'hello\' message. No common version')


    @async.coroutine
    def _device_link_version_exchange(self):
        VERSION_MAJOR = 300
        VERSION_MINOR = 0
        #
        app_log.debug('Waiting for a version exchange. Expected version is: {0}.{1}'.format(VERSION_MAJOR, VERSION_MINOR), **log_extra(self))
        reply = yield self._session.receive()
        if len(reply) != 3 or reply[0] != 'DLMessageVersionExchange':
            raise RuntimeError('Version exchange failed. Bad reply: {0}'.format(reply))
        #
        major = reply[1]
        minor = reply[2]
        if major > VERSION_MAJOR or (major == VERSION_MAJOR and minor > VERSION_MINOR):
            raise RuntimeError('Version exchange failed. Device version is: {0}.{1}'.format(major, minor))
        else:
            app_log.info('Device version is: {0}.{1}'.format(major, minor), **log_extra(self))
        #
        reply = yield self._session.fetch(device_link.create_message_dl_version_ok(VERSION_MAJOR, VERSION_MINOR))
        if 'DLMessageDeviceReady' not in reply:
            raise RuntimeError('Version exchange failed. The expected version is not accepted.'.format(reply))
        #
        app_log.info('The expected version is accepted.', **log_extra(self))

    def _device_link_send_status_response(self, code=0, status1=None, status2=None):
        self._session.send(device_link.create_message_status_response(code, status1, status2))

    def _device_link_send_process_message(self, message):
        self._session.send(device_link.create_message_process_message(message))

    @async.coroutine
    def _device_link_fetch_process_message(self, message):
        self._device_link_send_process_message(message)
        return (yield self._session.receive())
