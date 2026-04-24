""" decorators.py
"""
import contextlib
import functools
import logging

try:
    from singledispatch import singledispatch

except ImportError:  # pragma: no cover
    from functools import singledispatch


from .errors import PGPError

__all__ = ['classproperty',
           'sdmethod',
           'sdproperty',
           'KeyAction']


def classproperty(fget):
    class ClassProperty(object):
        def __init__(self, fget):
            self.fget = fget
            self.__doc__ = fget.__doc__

        def __get__(self, cls, owner):
            return self.fget(owner)

        def __set__(self, obj, value):  # pragma: no cover
            raise AttributeError("Read-only attribute")

        def __delete__(self, obj):  # pragma: no cover
            raise AttributeError("Read-only attribute")

    return ClassProperty(fget)


def sdmethod(meth):
    """
    This is a hack to monkey patch sdproperty to work as expected with instance methods.
    """
    sd = singledispatch(meth)

    def wrapper(obj, *args, **kwargs):
        pass

    wrapper.register = sd.register
    wrapper.dispatch = sd.dispatch
    wrapper.registry = sd.registry
    wrapper._clear_cache = sd._clear_cache
    functools.update_wrapper(wrapper, meth)
    return wrapper


def sdproperty(fget):
    def defset(obj, val):  # pragma: no cover
        raise TypeError(str(val.__class__))

    class SDProperty(property):
        def register(self, cls=None, fset=None):
            return self.fset.register(cls, fset)

        def setter(self, fset):
            pass

    return SDProperty(fget, sdmethod(defset))


class KeyAction(object):
    def __init__(self, *usage, **conditions):
        super(KeyAction, self).__init__()
        self.flags = set(usage)
        self.conditions = conditions

    @contextlib.contextmanager
    def usage(self, key, user):
        pass

    def check_attributes(self, key):
        pass

    def __call__(self, action):
        @functools.wraps(action)
        def _action(key, *args, **kwargs):
            pass

        return _action
