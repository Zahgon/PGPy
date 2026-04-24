""" subpacket.py
"""
import abc

from ..types import VersionedHeader

from ...decorators import sdproperty

from ...types import Dispatchable
from ...types import Header as _Header

__all__ = ['Header',
           'EmbeddedSignatureHeader',
           'SubPacket',
           'Signature',
           'UserAttribute',
           'Opaque']


class Header(_Header):
    @sdproperty
    def critical(self):
        raise NotImplementedError

    @critical.register(bool)
    def critical_bool(self, val):
        raise NotImplementedError

    @sdproperty
    def typeid(self):
        raise NotImplementedError

    @typeid.register(int)
    def typeid_int(self, val):
        raise NotImplementedError

    @typeid.register(bytes)
    @typeid.register(bytearray)
    def typeid_bin(self, val):
        raise NotImplementedError

    def __init__(self):
        raise NotImplementedError

    def parse(self, packet):
        raise NotImplementedError

    def __len__(self):
        raise NotImplementedError

    def __bytearray__(self):
        raise NotImplementedError


class EmbeddedSignatureHeader(VersionedHeader):
    def __bytearray__(self):
        raise NotImplementedError

    def parse(self, packet):
        raise NotImplementedError


class SubPacket(Dispatchable):
    __headercls__ = Header

    def __init__(self):
        raise NotImplementedError

    def __bytearray__(self):
        raise NotImplementedError

    def __len__(self):
        raise NotImplementedError

    def __repr__(self):
        raise NotImplementedError

    def update_hlen(self):
        raise NotImplementedError

    @abc.abstractmethod
    def parse(self, packet):  # pragma: no cover
        raise NotImplementedError


class Signature(SubPacket):
    __typeid__ = -1


class UserAttribute(SubPacket):
    __typeid__ = -1


class Opaque(Signature, UserAttribute):
    __typeid__ = None

    @sdproperty
    def payload(self):
        raise NotImplementedError

    @payload.register(bytes)
    @payload.register(bytearray)
    def payload_bin(self, val):
        raise NotImplementedError

    def __init__(self):
        raise NotImplementedError

    def __bytearray__(self):
        raise NotImplementedError

    def parse(self, packet):
        raise NotImplementedError
