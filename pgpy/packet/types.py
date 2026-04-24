""" types.py
"""
from __future__ import division

import abc
import copy

from ..constants import PacketTag

from ..decorators import sdproperty

from ..types import Dispatchable
from ..types import Field
from ..types import Header as _Header

__all__ = ['Header',
           'VersionedHeader',
           'Packet',
           'VersionedPacket',
           'Opaque',
           'Key',
           'Public',
           'Private',
           'Primary',
           'Sub',
           'MPI',
           'MPIs', ]


class Header(_Header):
    @sdproperty
    def tag(self):
        raise NotImplementedError

    @tag.register(int)
    @tag.register(PacketTag)
    def tag_int(self, val):
        raise NotImplementedError

    @property
    def typeid(self):
        raise NotImplementedError

    def __init__(self):
        raise NotImplementedError

    def __bytearray__(self):
        raise NotImplementedError

    def __len__(self):
        raise NotImplementedError

    def parse(self, packet):
        """
        There are two formats for headers

        old style
        ---------

        Old style headers can be 1, 2, 3, or 6 octets long and are composed of a Tag and a Length.
        If the header length is 1 octet (length_type == 3), then there is no Length field.

        new style
        ---------

        New style headers can be 2, 3, or 6 octets long and are also composed of a Tag and a Length.


        Packet Tag
        ----------

        The packet tag is the first byte, comprising the following fields:

        +-------------+----------+---------------+---+---+---+---+----------+----------+
        | byte        | 1                                                              |
        +-------------+----------+---------------+---+---+---+---+----------+----------+
        | bit         | 7        | 6             | 5 | 4 | 3 | 2 | 1        | 0        |
        +-------------+----------+---------------+---+---+---+---+----------+----------+
        | old-style   | always 1 | packet format | packet tag    | length type         |
        | description |          | 0 = old-style |               | 0 = 1 octet         |
        |             |          | 1 = new-style |               | 1 = 2 octets        |
        |             |          |               |               | 2 = 5 octets        |
        |             |          |               |               | 3 = no length field |
        +-------------+          +               +---------------+---------------------+
        | new-style   |          |               | packet tag                          |
        | description |          |               |                                     |
        +-------------+----------+---------------+-------------------------------------+

        :param packet: raw packet bytes
        """
        raise NotImplementedError


class VersionedHeader(Header):
    @sdproperty
    def version(self):
        raise NotImplementedError

    @version.register(int)
    def version_int(self, val):
        raise NotImplementedError

    def __init__(self):
        raise NotImplementedError

    def __bytearray__(self):
        raise NotImplementedError

    def parse(self, packet):  # pragma: no cover
        raise NotImplementedError


class Packet(Dispatchable):
    __typeid__ = -1
    __headercls__ = Header

    def __init__(self, _=None):
        raise NotImplementedError

    @abc.abstractmethod
    def __bytearray__(self):
        raise NotImplementedError

    def __len__(self):
        raise NotImplementedError

    def __repr__(self):
        raise NotImplementedError

    def update_hlen(self):
        raise NotImplementedError

    @abc.abstractmethod
    def parse(self, packet):
        raise NotImplementedError


class VersionedPacket(Packet):
    __headercls__ = VersionedHeader

    def __init__(self):
        raise NotImplementedError

    def __repr__(self):
        raise NotImplementedError


class Opaque(Packet):
    __typeid__ = None

    @sdproperty
    def payload(self):
        raise NotImplementedError

    @payload.register(bytearray)
    @payload.register(bytes)
    def payload_bin(self, val):
        raise NotImplementedError

    def __init__(self):
        raise NotImplementedError

    def __bytearray__(self):
        raise NotImplementedError

    def parse(self, packet):  # pragma: no cover
        raise NotImplementedError


# key marker classes for convenience
class Key(object):
    pass


class Public(Key):
    pass


class Private(Key):
    pass


class Primary(Key):
    pass


class Sub(Key):
    pass


# This is required for class MPI to work in both Python 2 and 3
long = int


class MPI(long):
    def __new__(cls, num):
        raise NotImplementedError

    def byte_length(self):
        raise NotImplementedError

    def to_mpibytes(self):
        raise NotImplementedError

    def __len__(self):
        raise NotImplementedError


class MPIs(Field):
    # this differs from MPI in that it's subclasses hold/parse several MPI fields
    # and, in the case of v4 private keys, also a String2Key specifier/information.
    __mpis__ = ()

    def __len__(self):
        raise NotImplementedError

    def __iter__(self):
        """yield all components of an MPI so it can be iterated over"""
        raise NotImplementedError

    def __copy__(self):
        raise NotImplementedError
