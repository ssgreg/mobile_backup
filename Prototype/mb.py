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

    @staticmethod
    @async.coroutine
    def make(channel_factory):
        app_log.info('Making UsbMuxDirectory...')
        directory = UsbMuxDirectory(channel_factory)
        directory._usbmux_client = yield directory._make_usbmux_client()
        directory._buid = yield directory._usbmux_client.read_buid()
        return directory

    @async.coroutine
    def objects(self):
        with (yield self._make_usbmux_client()) as service:
            devices = yield service.list_devices()
        return [Object(device, self._usbmux_client) for device in devices]

    @async.coroutine
    def wait_for_object(self, sn, connection_type=TYPE_USB):
        waiter = DeviceWaiter(sn, connection_type)
        with (yield self._make_usbmux_client()) as service:
#            print((yield service.read_pair_record()))
            yield service.listen(waiter.on_attached)
            device = yield waiter.wait()
        return Object(device, self._usbmux_client)

    @async.coroutine
    def _make_usbmux_client(self):
        service = yield usbmux.Client.make(self._channel_factory)
        return service

#
# Object
#

class Object:
    def __init__(self, device, usbmux_factory):
        self._device = device
        self._usbmux_factory = usbmux_factory

    def __str__(self):
        return str(self._device)

    @async.coroutine
    def afc_client(self):
        return (yield afc.Client.make(self._make_channel_to_device_service))

    @async.coroutine
    def _make_channel_to_port(self, port):
        with (yield self._usbmux_factory()) as usbmux_client:
            return (yield usbmux_client.turn_to_tunnel_to_device_service(self.did, port))

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
