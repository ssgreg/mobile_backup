# -*- coding: utf-8 -*-
#
# mb.py
# mb
#
# Created by Grigory Zubankov.
# Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#


import async


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
# Directory
#

class Directory:
    def __init__(self, service_factory):
        self._service_factory =  service_factory

    @async.coroutine
    def objects(self):
        service = yield self._service_factory()
        devices = yield service.list_devices()
        return [Object(device) for device in devices]

    @async.coroutine
    def wait_for_object(self, sn, connection_type=TYPE_USB):
        waiter = DeviceWaiter(sn, connection_type)
        service = yield self._service_factory()
        yield service.listen(waiter.on_attached)
        object = yield waiter.wait()
        return object


#
# Object
#

class Object:
    def __init__(self, device):
        self._device = device

    def __str__(self):
        return str(self._device)