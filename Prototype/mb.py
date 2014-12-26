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
        if device.sn == self._sn and device.connection_type == self._connection_type :
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
        not self._usbmux_client or self._usbmux_client.close()

    @staticmethod
    @async.coroutine
    def make(channel_factory):
        directory = UsbMuxDirectory(channel_factory)
        app_log.info('Making a UsbMuxDirectory...', **log_extra(directory))
        directory._usbmux_client = yield directory._make_usbmux_client()
        directory._buid = yield directory._usbmux_client.read_buid()
        app_log.debug('A UsbMuxDirectory is created.', **log_extra(directory))
        return directory

    @async.coroutine
    def objects(self):
        with (yield self._make_usbmux_client()) as service:
            devices = yield service.list_devices()
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
# Object
#

class Object:
    def __init__(self, device, buid, pair_record, channel_factory):
        self._device = device
        self._channel_factory = channel_factory

    def __str__(self):
        return str(self._device)

    @async.coroutine
    def afc_client(self):
        return (yield afc.Client.make(self._make_channel_to_device_service))

    @async.coroutine
    def _make_channel_to_port(self, port):
        return (yield self._channel_factory(self.did, port))

    @async.coroutine
    def _make_channel_to_device_service(self, name):
        with (yield lockdown.Client.make(self._make_channel_to_port)) as lockdown_client:
            port = yield lockdown_client.start_service(name)
            return (yield self._make_channel_to_port(port))

    @property
    def did(self):
        return self._device.did

    @property
    def sn(self):
        return self._device.sn
