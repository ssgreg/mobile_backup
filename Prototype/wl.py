#


#
# WorkflowLinkData
#

class WorkflowLinkData:
  def __init__(self, data, private_data):
    self.__dict__['__data'] = data
    self.__dict__['__private_data'] = private_data

  def __setattr__(self, name, value):
    self.__dict__['__data'][name] = value

  def __getattr__(self, name):
    if name in self.__dict__['__data']:
      return self.__dict__['__data'][name]
    elif name in self.__dict__['__private_data']:
      return self.__dict__['__private_data'][name]
    else:
      raise RuntimeError('Data: Key not found: {0}'.format(name))


#
# WorkflowLink
#

class WorkflowLink:
  def __init__(self, data=None, **kwargs):
    self.__next = None
    self.__blocked = True
    self.data = WorkflowLinkData(data, kwargs)

  def link(self, next):
    self.__next = next

  def blocked(self):
    return self.__blocked

  def start(self):
    self.__blocked = False
    self.proceed();

  def stop(self):
    self.__blocked = True
    self.block();
    if self.__next:
      self.__next.stop()

  def stop_next(self):
    if self.__next:
      self.__next.stop()

  def block(self):
    pass

  def proceed(self):
    self.next()

  def next(self):
    if self.blocked():
      raise RuntimeError('Failed to continue. WorkflowLink is blocked.')
    if self.__next:
      self.__next.start() 


def link(first, *wls):
  cur = first
  for wl in wls:
    cur.link(wl)
    cur = wl
  return (first, cur)


#
# ProxyWorkflowLink
#

class ProxyWorkflowLink(WorkflowLink):
  def __init__(self, on_perform, on_block=None):
    super().__init__()
    self.on_perform = on_perform
    self.on_block = on_block

  def block(self):
    if self.on_block:
      self.on_block()

  def proceed(self):
    if self.on_perform():
      self.next()


#
# WorkflowBatch
#

class WorkflowBatch(WorkflowLink):
  def __init__(self, first_wl, *wls):
    super().__init__()
    self.first_wl, self.last_wl = link(first_wl, *wls)
    self.last_wl.link(ProxyWorkflowLink(self.on_last_proceed, self.on_last_block))

  def proceed(self):
    self.first_wl.start()

  def block(self):
    self.first_wl.stop()

  def on_last_proceed(self):
    self.next()

  def on_last_block(self):
    self.stop_next()



# d1 = dict()
# d2 = dict(a=1)

# d = WorkflowLinkData(d1, d2)
# d.b = 'Test'
# print(d.b)

# print(d1)

# class TestWL(WorkflowLink):
#   def proceed(self):
#     print('a')
#     self.next()

# class TestWL1(WorkflowLink):
#   def proceed(self):
#     print('b')
#     self.next()

# class TestWL2(WorkflowLink):
#   def proceed(self):
#     print('c')
#     self.next()


# a = TestWL()
# b = TestWL1()
# c = TestWL2()

# w = WorkflowBatch(a, b, c)
# w.start()


