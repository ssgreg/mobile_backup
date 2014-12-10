# -*- coding: utf-8 -*-
# 
# idevice.py
#
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import afc
import lockdown
import usbmux
#
from logger import *
from tools import *
import wl


#
# InternalFindDeviceByDidOrSnWLink
#

class InternalFindDeviceByDidOrSnWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.device = None
    # use 'sn' by default
    if self.data.sn:
      self.data.device = next((x for x in self.data.devices if x.sn == self.data.sn), None)
    # or did if 'sn' is not specified
    elif self.data.did:
      self.data.device = next((x for x in self.data.devices if x.did == self.data.did), None)
    #
    if self.data.device:
      logger().debug('InternalFindDeviceByDidOrSnWLink: Found {0}'.format(self.data.device.display()))
      self.next()
    else:
      raise RuntimeError('There is no device with sn={0} and did={1}'.format(self.data.sn, self.data.did))


#
# Directory
#

class Directory:
  def __init__(self, connect):
    self.connect = connect
    self.data = dict(usbmux=usbmux.UsbMuxService(connect, None), connect=connect)

  def objects(self, on_result):
    pass

  def find_object(self, did, sn, on_result):
    self.workflow = wl.WorkflowBatch(
      usbmux.UsbMuxListDevicesWLink(self.data),
      InternalFindDeviceByDidOrSnWLink(self.data, did=did, sn=sn),
      ObjectMakeObjectWLink(self.data),
      wl.ProxyWorkflowLink(lambda: on_result(self.data['object']))
    )
    self.workflow.start()

  def close(self):
    self.data['usbmux'].close()


#
# DirectoryFindObjectWLink
#

class DirectoryFindObjectWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.directory.find_object(self.data.did, self.data.sn, lambda x: self.blocked() or self.on_find_object(x))
    self.stop_next()

  def on_find_object(self, dir_object):
    self.data.object = dir_object
    self.next()


#
# InternalObjectMakeAfcServiceWLink
#

class ObjectMakeAfcServiceWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.afc = afc.Service(self.data.service_connection)
    self.next()


#
# Object
#

class Object:
  def __init__(self, device, on_result):
    self.device = device
    self.data = dict(device=device, connect_to_service=lambda port, on_result: self.device.connect_to_service(port, on_result))
    #
    self.workflow = wl.WorkflowBatch(
      usbmux.UsbMuxDeviceReadPairRecordWLink(self.data),
      lockdown.LockdownMakeServiceWLink(self.data, buid=self.device.buid),
      wl.ProxyWorkflowLink(on_result))
    self.workflow.start()

  @property
  def did(self):
    return self.device.did

  @property
  def sn(self):
    return self.device.sn

  def afc_service(self, on_result):
    if not 'afc' in self.data:
      self.workflow = wl.WorkflowBatch(
        lockdown.LockdownStartServiceWLink(self.data, service_type=afc.AFC_SERVICE_TYPE, use_escrow_bag=False),
        ObjectMakeAfcServiceWLink(self.data),
        wl.ProxyWorkflowLink(lambda: on_result(self.data['afc'])))
      self.workflow.start()
    else:
      return on_result(self.data['afc'])

  def close(self):
    if 'lockdown' in self.data:
      self.data['lockdown'].close()
    if 'afc' in self.data:
      self.data['afc'].close()


#
# ObjectMakeObjectWLink
#

class ObjectMakeObjectWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.object = Object(self.data.device, lambda: self.blocked() or self.next())
    self.stop_next()


#
# ObjectGetAfcWLink
#

class ObjectGetAfcWLink(wl.WorkflowLink):
  def proceed(self):
    self.data.object.afc_service(lambda x: self.blocked() or self.on_afc_service(x))
    self.stop_next()

  def on_afc_service(self, afc):
    self.afc = afc
    self.next()
