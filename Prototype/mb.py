# -*- coding: utf-8 -*-
#
# mb.py
# mb
#
# Created by Grigory Zubankov.
# Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


import afc
import async
import lockdown
import mb2
import usbmux
from logger import app_log
from tools import log_extra


TYPE_NETWORK = 'Network'
TYPE_USB = 'USB'


#
# DeviceWaiter
#

class DeviceWaiter:
    def __init__(self, sn, connection_type):
        self._sn = sn
        self._connection_type = connection_type
        self._future = async.Future()

    @async.coroutine
    def wait(self):
        yield self._future
        return self._future.result()


    def on_attached(self, device):
        if device.sn == self._sn and device.connection_type == self._connection_type:
            self._future.set_result(device)


#
# UsbMuxDirectory
#

class UsbMuxDirectory:
    def __init__(self, channel_factory):
        self._channel_factory = channel_factory
        self._usbmux_client = None
        self._buid = None

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self._usbmux_client:
            self._usbmux_client.close()
            app_log.info('Closed', **log_extra(self))

    @staticmethod
    @async.coroutine
    def make(channel_factory):
        directory = UsbMuxDirectory(channel_factory)
        yield directory.open(channel_factory)
        return directory

    @async.coroutine
    def open(self, channel_factory):
        app_log.info('Trying to open UsbMuxDirectory...', **log_extra(self))
        self._usbmux_client = yield self._make_usbmux_client()
        try:
            self._buid = yield self._usbmux_client.read_buid()
        except Exception as e:
            self._usbmux_client.close()
            raise e
        app_log.debug('A UsbMuxDirectory is opened.', **log_extra(self))

    @async.coroutine
    def objects(self):
        devices = yield self._usbmux_client.list_devices()
        return [(yield self._make_object(device)) for device in devices]

    @async.coroutine
    def wait_for_object(self, sn, connection_type=TYPE_USB):
        app_log.debug('Waiting for an object with sn={0}, type={1}'.format(sn, connection_type), **log_extra(self))
        waiter = DeviceWaiter(sn, connection_type)
        with (yield self._make_usbmux_client()) as service:
            yield service.turn_to_listen_channel(waiter.on_attached)
            device = yield waiter.wait()
        app_log.info('Done. Object={0}'.format(device), **log_extra(self))
        return (yield self._make_object(device))

    @async.coroutine
    def _make_usbmux_client(self):
        service = yield usbmux.Client.make(self._channel_factory)
        return service

    @async.coroutine
    def _make_object(self, device):
        pair_record = yield self._usbmux_client.read_pair_record(device.sn)
        return Object(device, self._buid, pair_record, self._make_channel_to_port)

    @async.coroutine
    def _make_channel_to_port(self, did, port):
        with (yield self._make_usbmux_client()) as service:
            return (yield service.turn_to_tunnel_to_device_service(did, port))


#
# SingleDeviceDirectory
#

class SingleDeviceDirectory:
    def __init__(self, channel_factory, sn, buid, pair_record):
        self._channel_factory = channel_factory
        self._sn = sn
        self._buid = buid
        self._pair_record = pair_record

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        pass

    @staticmethod
    @async.coroutine
    def make(channel_factory, sn, buid, pair_record):
        directory = SingleDeviceDirectory(channel_factory, sn, buid, pair_record)
        yield directory.open(channel_factory)
        return directory

    @async.coroutine
    def open(self, channel_factory):
        app_log.info('Trying to open directory...', **log_extra(self))
        # self._usbmux_client = yield self._make_usbmux_client()
        # try:
        #     self._buid = yield self._usbmux_client.read_buid()
        # except Exception as e:
        #     self._usbmux_client.close()
        #     raise e
        app_log.debug('The directory is opened.', **log_extra(self))

    @async.coroutine
    def objects(self):
        return self._make_object()

    @async.coroutine
    def wait_for_object(self, sn, connection_type=TYPE_NETWORK):
        app_log.debug('Waiting for an object with sn={0}, type={1}'.format(sn, connection_type), **log_extra(self))
        if connection_type == TYPE_USB:
            raise RuntimeError('Unsupported connection type.')
        if sn != self._sn:
            raise RuntimeError('Invalid serial number.')
        waiter = DeviceWaiter(sn, connection_type)

        channel = yield self._make_channel(0, lockdown.LOCKDOWN_SERVICE_PORT)
        channel.close()

        object = self._make_object()
        app_log.info('Done. Object={0}'.format(object), **log_extra(self))
        return object

    @async.coroutine
    def _make_channel(self, did, port):
        channel =  self._channel_factory(port)
        yield channel.connect_async()
        return channel

    def _make_object(self):
        info = dict(DeviceID=0, Properties=dict(SerialNumber=self._sn, ConnectionType=TYPE_NETWORK))
        return Object(usbmux.Device(info), self._buid, self._pair_record, self._make_channel)


#
# Object
#

class Object:
    def __init__(self, device, buid, pair_record, channel_factory):
        self._buid = buid
        self._pair_record = pair_record
        self._device = device
        self._channel_factory = channel_factory

    def __str__(self):
        return str(self._device)

    @async.coroutine
    def get_value(self, domain=None, key=None):
        with (yield lockdown.Client.make(self._pair_record, self._buid, self._make_channel_to_port)) as lockdown_client:
            return (yield lockdown_client.get_value(domain, key))

    @async.coroutine
    def afc_client(self):
        return (yield afc.Client.make(self._make_channel_to_device_service))

    @async.coroutine
    def mb2_client(self):
        return (yield mb2.Client.make(self._make_channel_to_device_service))

    @async.coroutine
    def _make_channel_to_port(self, port):
        return (yield self._channel_factory(self.did, port))

    @async.coroutine
    def _make_channel_to_device_service(self, service, use_escrow_bag=False):
        with (yield lockdown.Client.make(self._pair_record, self._buid, self._make_channel_to_port)) as lockdown_client:
            port, ssl_needed = yield lockdown_client.start_service(service, use_escrow_bag)
            channel = yield self._make_channel_to_port(port)
            if ssl_needed:
                channel.enable_ssl(self._pair_record['HostCertificate'], self._pair_record['HostPrivateKey'])
            return channel

    @property
    def did(self):
        return self._device.did

    @property
    def sn(self):
        return self._device.sn
