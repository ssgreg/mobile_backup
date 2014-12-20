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
from logger import *
import async
import wl


def create_usbmux_message(command):
    # kLibUSBMuxVersion = 3 - allows to get notifications about network devices
    return dict(
        BundleID='org.acronis.usbmuxd',
        ClientVersionString='1.0.0',
        MessageType=command,
        ProgName='Acronis Mobile Backup',
        kLibUSBMuxVersion=3)


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
        return struct.pack('<IIII', self.size + self.SIZE, self.version, self.mtype, self.tag)

    @classmethod
    def decode(cls, encoded):
        size, version, mtype, tag = struct.unpack_from('<IIII', encoded)
        return UsbMuxHeader(size - cls.SIZE, version, mtype, tag)


#
# Device
#

class Device:
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
    def pid(self):
        return self.__info['Properties']['ProductID'] if 'ProductID' in self.__info['Properties'] else None

    @property
    def info(self):
        return self.__info

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
        yield self._channel.connect()

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
        reply_header_data = yield self._channel.read(UsbMuxHeader.SIZE)
        reply_header = UsbMuxHeader.decode(reply_header_data)
        self._validate_header(reply_header, tag)
        reply_data = yield self._channel.read(reply_header.size)
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
        self._session = InternalSession(channel_factory())
        self._buid = None

    @staticmethod
    @async.coroutine
    def connect(channel_factory):
        client = yield Client(channel_factory)._connect()
        return client

    @async.coroutine
    def list_devices(self):
        reply = yield self._session.fetch(create_usbmux_message_list_devices())
        if 'DeviceList' not in reply:
            raise RuntimeError('Failed to list devices')
        #
        devices = [Device(self, x, self._buid) for x in reply['DeviceList']]
        # remove all non-USB devices
        devices = [x for x in devices if x.connected_via_usb()]
        logger().info('Visible devices count = {0}'.format(len(devices)))
        return devices

    @async.coroutine
    def read_pair_record(self, sn):
        logger().info('Reading pair record of a device with a sn = {0}'.format(sn))
        reply = yield self._session.fetch(create_usbmux_message_read_pair_record(sn))
        #
        if 'PairRecordData' not in reply:
            raise RuntimeError('Failed to read pair record')
        pair_record = plistlib.loads(reply['PairRecordData'])
        logger().info('Done. HostID = {0}'.format(pair_record['HostID']))
        return pair_record


    @async.coroutine
    def connect_to_service(self, did, port):
        logger().info('Connecting to a service with did = {0} and port = {1}'.format(did, port))
        reply = yield self._session.fetch(create_usbmux_message_connect(did, port))
        #
        if reply['Number'] != 0:
            raise RuntimeError('Failed. Error = {0}'.format(reply['Number']))
        logger().info('Done')


    @async.coroutine
    def listen(self, on_attached, on_detached=None):
        self._session.on_notification = lambda attached, info:\
            self._on_listen_notification(on_attached, on_detached, attached, info)
        reply = yield self._session.fetch(create_usbmux_message_listen())
        if 'Number' not in reply or reply['Number'] != 0:
            raise RuntimeError('Failed to listen with error: {0}'.format(reply['Number']))

    @async.coroutine
    def close(self):
        yield self._session.stop()

    @async.coroutine
    def _read_buid(self):
        reply = yield self._session.fetch(create_usbmux_message_read_buid())
        if 'BUID' not in reply:
            raise RuntimeError('Failed to read BUID')
        #
        buid = reply['BUID']
        logger().info('BUID = {0}'.format(buid))
        return buid

    @async.coroutine
    def _connect(self):
        yield self._session.start()
        self._buid = yield self._read_buid()
        return self

    def _on_listen_notification(self, on_attached, on_detached, attached, info):
        if attached and on_attached:
            on_attached(Device(self, info, self._buid))
        if not attached and on_detached:
            on_detached(info['DeviceID'])

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()
