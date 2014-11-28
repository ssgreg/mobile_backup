
class WorkflowLink(object):
  def __init__(self, data=None, **kwargs):
    self.__next = None
    self.data = data or {}
    if kwargs:
      self.data = dict(self.data, **kwargs)

  def link(self, next):
    self.__next = next

  def start(self):
    self.proceed();

  def stop(self):
    self.block();
    if self.__next:
      self.__next.stop()

  def stop_next(self):
    if self.__next:
      self.__next.stop()

  def block(self):
    pass

  def proceed(self):
    self.next();

  def next(self):
    if self.__next:
      self.__next.start() 




def link(first, *wls):
  cur = first
  for wl in wls:
    cur.link(wl)
    cur = wl
  return first


# class TestWL(WorkflowLink):
#   def proceed(self):
#     print 'a'
#     self.next()

# class TestWL1(WorkflowLink):
#   def proceed(self):
#     print 'b'
#     self.next()

# class TestWL2(WorkflowLink):
#   def proceed(self):
#     print 'c'
#     self.next()


# a = TestWL()
# b = TestWL1()
# c = TestWL2()

# w = link_workflow(a, b, c)
# w.start()


