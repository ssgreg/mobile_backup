# -*- coding: utf-8 -*-
#
# usbmux.py
# UsbMux service
#
# Created by Grigory Zubankov.
# Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import plistlib
import struct
#
import about
import async
from logger import app_log


def create_message(command):
    # kLibUSBMuxVersion = 3 - allows to get notifications about network devices
    return dict(
        BundleID=about.APPLICATION_ID,
        ClientVersionString=about.APPLICATION_VERSION,
        MessageType=command,
        ProgName=about.APPLICATION_NAME,
        kLibUSBMuxVersion=3)


def create_message_list_devices():
    return create_message('ListDevices')


def create_message_read_buid():
    return create_message('ReadBUID')


def create_message_listen():
    return create_message('Listen')


def create_message_connect(did, port):
    # Note! The port should be passed in a big endian format
    plist_data = create_message('Connect')
    plist_data.update(
        DeviceID=did,
        PortNumber=struct.unpack('>H', struct.pack('@H', port))[0]
    )
    return plist_data


def create_message_read_pair_record(sn):
    plist_data = create_message('ReadPairRecord')
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
        return struct.pack('<IIII', self.size + self.SIZE, self.version, self.mtype, self.tag)

    @classmethod
    def decode(cls, encoded):
        size, version, mtype, tag = struct.unpack_from('<IIII', encoded)
        return UsbMuxHeader(size - cls.SIZE, version, mtype, tag)


#
# Device
#

class Device:
    def __init__(self, info):
        self._info = info

    def connected_via_usb(self):
        return self.connection_type == 'USB'

    @property
    def did(self):
        return self._info['DeviceID']

    @property
    def sn(self):
        return self._info['Properties']['SerialNumber']

    @property
    def connection_type(self):
        # USB or Network
        return self._info['Properties']['ConnectionType']

    @property
    def pid(self):
        return self._info['Properties']['ProductID'] if 'ProductID' in self._info['Properties'] else None

    @property
    def info(self):
        return self._info

    def __str__(self):
        return 'Device | did = {0} | sn = {1} | type = {2}'.format(self.did, self.sn, self.connection_type)


#
# InternalSession
#

class InternalSession:
    TAG_NOTIFICATION = 0
    USBMUX_VERSION = 1
    PLIST_MTYPE = 8
    MAX_REPLY_SIZE = 1 * (1024 * 1024)  # 1 MB

    def __init__(self, channel):
        self._channel = channel
        self._tag = self.TAG_NOTIFICATION + 1
        self.on_notification = lambda action, msg: None
        self._channel.on_notification = self._on_notification

    @async.coroutine
    def start(self):
        yield self._channel.connect_async()

    @async.coroutine
    def fetch(self, msg):
        request_data = plistlib.dumps(msg)
        request_header_data = UsbMuxHeader(len(request_data), self.USBMUX_VERSION, self.PLIST_MTYPE, self._tag).encode()
        #
        self._channel.write(request_header_data)
        self._channel.write(request_data)
        #
        message = yield self._read_message(self._tag)
        #
        self._tag += 1
        return message

    @async.coroutine
    def stop(self):
        yield self._channel.close()

    def release_channel(self):
        channel, self._channel = self._channel, None
        return channel

    def _validate_header(self, header, tag):
        if header.tag != tag:
            raise RuntimeError('Incorrect usbmux header tag!')
        if header.mtype != self.PLIST_MTYPE:
            raise RuntimeError('Incorrect usbmux header encoding type!')
        if header.version != self.USBMUX_VERSION:
            raise RuntimeError('Incorrect usbmux header version!')
        if header.size > self.MAX_REPLY_SIZE:
            raise RuntimeError('Usbmux header size is too big!')

    @async.coroutine
    def _read_message(self, tag):
        reply_header_data = yield self._channel.read_async(UsbMuxHeader.SIZE)
        reply_header = UsbMuxHeader.decode(reply_header_data)
        self._validate_header(reply_header, tag)
        reply_data = yield self._channel.read_async(reply_header.size)
        return plistlib.loads(reply_data)

    @async.coroutine
    def _on_notification(self):
        message = yield self._read_message(self.TAG_NOTIFICATION)
        self.on_notification(message['MessageType'] == 'Attached', message)


#
# Client
#

class Client:
    def __init__(self, channel_factory):
        self._channel_factory = channel_factory
        self._session = InternalSession(channel_factory())

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    @staticmethod
    @async.coroutine
    def make(channel_factory):
        return (yield Client(channel_factory)._connect())

    @async.coroutine
    def connect_to_device_service(self, did, port):
        with (yield Client.make(self._channel_factory)) as client:
            return (yield client.turn_to_tunnel_to_device_service(did, port))

    @async.coroutine
    def close(self):
        yield self._session.stop()

    @async.coroutine
    def list_devices(self):
        reply = yield self._session.fetch(create_message_list_devices())
        if 'DeviceList' not in reply:
            raise RuntimeError('Failed to list devices')
        #
        devices = [Device(x) for x in reply['DeviceList']]
        # remove all non-USB devices
        devices = [x for x in devices if x.connected_via_usb()]
        app_log.info('Visible devices count = {0}'.format(len(devices)))
        return devices

    @async.coroutine
    def read_pair_record(self, sn):
        app_log.info('Reading pair record of a device with a sn = {0}'.format(sn))
        reply = yield self._session.fetch(create_message_read_pair_record(sn))
        #
        if 'PairRecordData' not in reply:
            raise RuntimeError('Failed to read pair record')
        pair_record = plistlib.loads(reply['PairRecordData'])
        app_log.info('Done. HostID = {0}'.format(pair_record['HostID']))
        return pair_record

    @async.coroutine
    def listen(self, on_attached, on_detached=None):
        self._session.on_notification = lambda attached, info:\
            self._on_listen_notification(on_attached, on_detached, attached, info)
        reply = yield self._session.fetch(create_message_listen())
        if 'Number' not in reply or reply['Number'] != 0:
            raise RuntimeError('Failed to listen with error: {0}'.format(reply['Number']))

    @async.coroutine
    def turn_to_tunnel_to_device_service(self, did, port):
        app_log.info('Connecting to a service with did = {0} and port = {1}'.format(did, port))
        reply = yield self._session.fetch(create_message_connect(did, port))
        #
        if reply['Number'] != 0:
            raise RuntimeError('Failed. Error = {0}'.format(reply['Number']))
        app_log.info('Done')
        return self._session.release_channel()

    @async.coroutine
    def read_buid(self):
        reply = yield self._session.fetch(create_message_read_buid())
        if 'BUID' not in reply:
            raise RuntimeError('Failed to read BUID')
        #
        buid = reply['BUID']
        app_log.info('BUID = {0}'.format(buid))
        print('buid', app_log)
        return buid

    @async.coroutine
    def _connect(self):
        yield self._session.start()
        return self

    def _on_listen_notification(self, on_attached, on_detached, attached, info):
        if attached and on_attached:
            on_attached(Device(info))
        if not attached and on_detached:
            on_detached(info['DeviceID'])
