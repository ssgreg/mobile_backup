# -*- coding: utf-8 -*-
# 
# main.py
# start point
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import argparse
import traceback
#
from ioloop import *
from logger import app_log, enable_pretty_logging
import afc
import logging
import async
import usbmux
import mb


def make_channel():
    if (sys.platform == 'darwin'):
        return SocketChannel(address=r'/var/run/usbmuxd', family=socket.AF_UNIX)
    else:
        return SocketChannel(address=('127.0.0.1', 27015))


#
# TestGetDeviceList
#

class TestGetDeviceList:
    @async.coroutine
    def start(self):
        usbmux_client = yield usbmux.Client.connect(make_channel)
        devices = yield self.usbmux_client.list_devices()
        [print(device) for device in devices]
        usbmux_client.close()


#
# TestGetDeviceListen
#

class TestListenForDevices:
    def __init__(self, timeout):
        self.usbmux = None
        IOLoop.instance().scheduler.enter(timeout, 1, self._stop, ())

    @async.coroutine
    def start(self):
        self.usbmux = yield usbmux.Client.make(make_channel)
        yield self.usbmux.listen(self._on_attached, self._on_detached)

    def _on_attached(self, device):
        print('Attached:', device)

    def _on_detached(self, device_id):
        print('Detached: Device with did =', device_id)

    def _stop(self):
        self.usbmux.close()


#
# TestBackup
#

class TestBackup:
    def __init__(self, did, sn):
        self.sn = sn

    @async.coroutine
    def start(self):
        with (yield mb.UsbMuxDirectory.make(make_channel)) as directory:
            object = yield directory.wait_for_object(self.sn, connection_type=mb.TYPE_USB)
            print(object)

            folder = '/Users/igreg/Documents'
            with (yield object.mb2_client()) as mb2_client:
                mb2_client.request_backup(object.sn, object.sn)
                while True:
                    reply = yield mb2_client.receive_message()
                    print(reply)
                    if reply[0] == 'DLMessageDownloadFiles':
                        mb2_client.send_files(folder, reply[1])
                    if reply[0] == 'DLContentsOfDirectory':
                        mb2_client.send_directory_contents(folder, reply[1])
                    if reply[0] == 'DLMessageGetFreeDiskSpace':
                        mb2_client.send_free_disk_space(folder)
                    if reply[0] == 'DLMessageCreateDirectory':
                        mb2_client.send_create_directory(folder, reply[1])
                    if reply[0] == 'DLMessageUploadFiles':
                        break

            # res = yield object.get_value('com.apple.mobile.backup', 'WillEncrypt')
            # print(res)
            # with (yield object.afc_client()) as afc_client:
            #     content = yield afc_client.read_directory('/')
            #     print(content)

                # yield afc_client.file_info('/Books/iBooksData2.plist')
                # handle = yield afc_client.open_file(path='/Books/iBooksData2.plist', mode=afc.FileOpenMode.READ_ONLY)
                #
                # block_size = 65535
                # data = b''
                # while True:
                #     block = yield afc_client.read_file(handle, block_size)
                #     data += block
                #     if len(block) < block_size:
                #         break
                #
                # print(len(data))

                # handle = yield afc_client.open_file(path='/com.apple.itunes.lock_sync', mode=afc.FileOpenMode.READ_WRITE)
                # res = yield afc_client.lock_file(handle=handle, mode=afc.FileLockMode.EXCLUSIVE)
                # res = yield afc_client.lock_file(handle=handle, mode=afc.FileLockMode.UNLOCK)


def configure_argparse():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='List of commands', dest='command')
    #
    list_parser = subparsers.add_parser('list', help='List')
  #  list_parser.set_defaults(func=lis)
    #
    listen_parser = subparsers.add_parser('listen', help='Listen')
    listen_parser.add_argument('--timeout', '-t', type=int, default=10, help='timeout in seconds')
    #
    test_parser = subparsers.add_parser('test', help='Test')
    test_parser.add_argument('--did', type=int, help='did')
    test_parser.add_argument('--sn', type=str, help='sn')
    return parser


def command_list(args):
    return TestGetDeviceList()

def command_listen(args):
   return TestListenForDevices(args.timeout)

def command_test(args):
    return TestBackup(args.did, args.sn)

def exit_command(future, cmd):
    try:
        future.result()
    except Exception:
        print(traceback.format_exc())


def main():
    print("Acronis Mobile Backup")
    enable_pretty_logging(logging.DEBUG)
    app_log.info('Current platform: {0}'.format(sys.platform))

    commands = {
        'list': command_list,
        'listen': command_listen,
        'test': command_test
    }
    args = configure_argparse().parse_args()

    cmd = commands[args.command](args)
    cmd.start().add_done_callback(lambda f: exit_command(f, cmd))
    IOLoop.instance().start()


# from wakeonlan import wol
# wol.send_magic_packet('28.E1.4C.CB.C4.22')

main()
