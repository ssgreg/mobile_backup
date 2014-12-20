# -*- coding: utf-8 -*-
# 
# async.py
# async
#
#  Created by Grigory Zubankov.
#  Copyright (c) 2014 Grigory Zubankov. All rights reserved.
#

import types
import sys

#
# Future
#

class Future(object):
    def __init__(self):
        self._done = False
        self._result = None
        self._exception = None
        self._exc_info = None
        self._callbacks = []

    def running(self):
        return not self._done

    def done(self):
        return self._done

    def result(self, timeout=None):
        if self._result is not None:
            return self._result
        if self._exc_info is not None:
            raise self._exc_info[1].with_traceback(self._exc_info[2])
        elif self._exception is not None:
            raise self._exception
        self._check_done()
        return self._result

    def exception(self, timeout=None):
        if self._exception is not None:
            return self._exception
        else:
            self._check_done()
            return None

    def add_done_callback(self, fn):
        if self._done:
            fn(self)
        else:
            self._callbacks.append(fn)

    def set_result(self, result):
        self._result = result
        self._set_done()

    def set_exception(self, exception):
        self._exception = exception
        self._set_done()

    def exc_info(self):
        return self._exc_info

    def set_exc_info(self, exc_info):
        self._exc_info = exc_info
        self.set_exception(exc_info[1])

    def _check_done(self):
        if not self._done:
            raise Exception("DummyFuture does not support blocking for results")

    def _set_done(self):
        self._done = True
        for cb in self._callbacks:
            try:
                cb(self)
            except Exception:
                print('exception calling callback {0} for {1}'.format(cb, self))
        self._callbacks = None


#
# MyRunner
#

class MyRunner:
    def __init__(self, gen, future, yielded):
        self.gen = gen
        self.future = None
        self.result_future = future
        self.yeilded = yielded
        #
        if self.handle_yield(yielded):
            self.run()

    def run(self):
        while True:
            future = self.future
            if not future.done():
                return
            try:
                try:
                    value = future.result()
                except Exception:
                    yielded = self.gen.throw(*sys.exc_info())
                else:
                    yielded = self.gen.send(value)
            except StopIteration as e:
                self.result_future.set_result(getattr(e, 'value', None))
                self.future = None
                self.result_future = None
                return
            except Exception:
                self.result_future.set_exc_info(sys.exc_info())
                self.future = None
                self.result_future = None
                return
            if not self.handle_yield(yielded):
                return

    def handle_yield(self, yielded):
        self.future = yielded
        if not self.future.done():
            self.future.add_done_callback(lambda f: self.run())
            return False
        return True


#
# coroutine
#

def coroutine(func):
  def wrapper(*args, **kwargs):
    future = Future()
    try:
      result = func(*args, **kwargs)
    except StopIteration as e:
      result = getattr(e, 'value', None)
    except Exception:
      future.set_exc_info(sys.exc_info())
      return future
    else:
      if isinstance(result, types.GeneratorType):
        try:
          yielded = next(result)
        except StopIteration as e:
            future.set_result(getattr(e, 'value', None))
        except Exception:
            future.set_exc_info(sys.exc_info())
        else:
          MyRunner(result, future, yielded)
        return future
    #
    future.set_result(result)
    return future
  return wrapper

