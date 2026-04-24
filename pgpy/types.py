""" types.py
"""
from __future__ import division

import abc
import base64
import binascii
import bisect
import codecs
import collections
import operator
import os
import re
import warnings
import weakref

from enum import EnumMeta
from enum import IntEnum

from .decorators import sdproperty

from .errors import PGPError

__all__ = ['Armorable',
           'ParentRef',
           'PGPObject',
           'Field',
           'Fingerprint',
           'FlagEnum',
           'FlagEnumMeta',
           'Header',
           'MetaDispatchable',
           'Dispatchable',
           'SignatureVerification',
           'Fingerprint',
           'SorteDeque']


class Armorable(metaclass=abc.ABCMeta):
    __crc24_init = 0x0B704CE
    __crc24_poly = 0x1864CFB

    __armor_fmt = '-----BEGIN PGP {block_type}-----\n' \
                  '{headers}\n' \
                  '{packet}\n' \
                  '={crc}\n' \
                  '-----END PGP {block_type}-----\n'

    # the re.VERBOSE flag allows for:
    #  - whitespace is ignored except when in a character class or escaped
    #  - anything after a '#' that is not escaped or in a character class is ignored, allowing for comments
    __armor_regex = re.compile(r"""# This capture group is optional because it will only be present in signed cleartext messages
                         (^-{5}BEGIN\ PGP\ SIGNED\ MESSAGE-{5}(?:\r?\n)
                          (Hash:\ (?P<hashes>[A-Za-z0-9\-,]+)(?:\r?\n){2})?
                          (?P<cleartext>(.*\r?\n)*(.*(?=\r?\n-{5})))(?:\r?\n)
                         )?
                         # armor header line; capture the variable part of the magic text
                         ^-{5}BEGIN\ PGP\ (?P<magic>[A-Z0-9 ,]+)-{5}(?:\r?\n)
                         # try to capture all the headers into one capture group
                         # if this doesn't match, m['headers'] will be None
                         (?P<headers>(^.+:\ .+(?:\r?\n))+)?(?:\r?\n)?
                         # capture all lines of the body, up to 76 characters long,
                         # including the newline, and the pad character(s)
                         (?P<body>([A-Za-z0-9+/]{1,76}={,2}(?:\r?\n))+)
                         # capture the armored CRC24 value
                         ^=(?P<crc>[A-Za-z0-9+/]{4})(?:\r?\n)
                         # finally, capture the armor tail line, which must match the armor header line
                         ^-{5}END\ PGP\ (?P=magic)-{5}(?:\r?\n)?
                         """, flags=re.MULTILINE | re.VERBOSE)

    @property
    def charset(self):
        pass

    @charset.setter
    def charset(self, encoding):
        pass

    @staticmethod
    def is_ascii(text):
        if isinstance(text, str):
            return bool(re.match(r'^[ -~\r\n\t]*$', text, flags=re.ASCII))

        if isinstance(text, (bytes, bytearray)):
            return bool(re.match(br'^[ -~\r\n\t]*$', text, flags=re.ASCII))

        raise TypeError("Expected: ASCII input of type str, bytes, or bytearray")  # pragma: no cover

    @staticmethod
    def is_armor(text):
        """
        Whether the ``text`` provided is an ASCII-armored PGP block.
        :param text: A possible ASCII-armored PGP block.
        :raises: :py:exc:`TypeError` if ``text`` is not a ``str``, ``bytes``, or ``bytearray``
        :returns: Whether the text is ASCII-armored.
        """
        pass

    @staticmethod
    def ascii_unarmor(text):
        """
        Takes an ASCII-armored PGP block and returns the decoded byte value.

        :param text: An ASCII-armored PGP block, to un-armor.
        :raises: :py:exc:`ValueError` if ``text`` did not contain an ASCII-armored PGP block.
        :raises: :py:exc:`TypeError` if ``text`` is not a ``str``, ``bytes``, or ``bytearray``
        :returns: A ``dict`` containing information from ``text``, including the de-armored data.
        It can contain the following keys: ``magic``, ``headers``, ``hashes``, ``cleartext``, ``body``, ``crc``.
        """
        m = {'magic': None, 'headers': None, 'body': bytearray(), 'crc': None}
        if not Armorable.is_ascii(text):
            m['body'] = bytearray(text)
            return m

        if isinstance(text, (bytes, bytearray)):  # pragma: no cover
            text = text.decode('latin-1')

        m = Armorable.__armor_regex.search(text)

        if m is None:  # pragma: no cover
            raise ValueError("Expected: ASCII-armored PGP data")

        m = m.groupdict()

        if m['hashes'] is not None:
            m['hashes'] = m['hashes'].split(',')

        if m['headers'] is not None:
            m['headers'] = collections.OrderedDict(re.findall('^(?P<key>.+): (?P<value>.+)$\n?', m['headers'], flags=re.MULTILINE))

        if m['body'] is not None:
            try:
                m['body'] = bytearray(base64.b64decode(m['body'].encode()))

            except (binascii.Error, TypeError) as ex:
                raise PGPError(str(ex)) from ex

        if m['crc'] is not None:
            m['crc'] = Header.bytes_to_int(base64.b64decode(m['crc'].encode()))
            if Armorable.crc24(m['body']) != m['crc']:
                warnings.warn('Incorrect crc24', stacklevel=3)

        return m

    @staticmethod
    def crc24(data):
        # CRC24 computation, as described in the RFC 4880 section on Radix-64 Conversions
        #
        # The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted to
        # four characters of radix-64 encoding by the same MIME base64
        # transformation, preceded by an equal sign (=).  The CRC is computed
        # by using the generator 0x864CFB and an initialization of 0xB704CE.
        # The accumulation is done on the data before it is converted to
        # radix-64, rather than on the converted data.
        crc = Armorable.__crc24_init

        if not isinstance(data, bytearray):
            data = iter(data)

        for b in data:
            crc ^= b << 16

            for i in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= Armorable.__crc24_poly

        return crc & 0xFFFFFF

    @abc.abstractproperty
    def magic(self):
        """The magic string identifier for the current PGP type"""

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as file:
            obj = cls()
            data = bytearray(os.path.getsize(filename))
            file.readinto(data)

        po = obj.parse(data)

        if po is not None:
            return (obj, po)

        return obj  # pragma: no cover

    @classmethod
    def from_blob(cls, blob):
        pass

    def __init__(self):
        super(Armorable, self).__init__()
        self.ascii_headers = collections.OrderedDict()

    def __str__(self):
        payload = base64.b64encode(self.__bytes__()).decode('latin-1')
        payload = '\n'.join(payload[i:(i + 64)] for i in range(0, len(payload), 64))

        return self.__armor_fmt.format(
            block_type=self.magic,
            headers=''.join('{key}: {val}\n'.format(key=key, val=val) for key, val in self.ascii_headers.items()),
            packet=payload,
            crc=base64.b64encode(PGPObject.int_to_bytes(self.crc24(self.__bytes__()), 3)).decode('latin-1')
        )

    def __copy__(self):
        obj = self.__class__()
        obj.ascii_headers = self.ascii_headers.copy()

        return obj


class ParentRef(object):
    # mixin class to handle weak-referencing a parent object
    @property
    def _parent(self):
        pass

    @_parent.setter
    def _parent(self, parent):
        pass

    @property
    def parent(self):
        pass

    def __init__(self):
        super(ParentRef, self).__init__()
        self._parent = None


class PGPObject(metaclass=abc.ABCMeta):

    @staticmethod
    def int_byte_len(i):
        return (i.bit_length() + 7) // 8

    @staticmethod
    def bytes_to_int(b, order='big'):  # pragma: no cover
        """convert bytes to integer"""

        return int.from_bytes(b, order)

    @staticmethod
    def int_to_bytes(i, minlen=1, order='big'):  # pragma: no cover
        """convert integer to bytes"""
        blen = max(minlen, PGPObject.int_byte_len(i), 1)

        return i.to_bytes(blen, order)

    @staticmethod
    def text_to_bytes(text):
        if text is None:
            return text

        # if we got bytes, just return it
        if isinstance(text, (bytearray, bytes)):
            return text

        # if we were given a unicode string, or if we translated the string into utf-8,
        # we know that Python already has it in utf-8 encoding, so we can now just encode it to bytes
        return text.encode('utf-8')

    @staticmethod
    def bytes_to_text(text):
        pass

    @abc.abstractmethod
    def parse(self, packet):
        """this method is too abstract to understand"""

    @abc.abstractmethod
    def __bytearray__(self):
        """
        Returns the contents of concrete subclasses in a binary format that can be understood by other OpenPGP
        implementations
        """

    def __bytes__(self):
        """
        Return the contents of concrete subclasses in a binary format that can be understood by other OpenPGP
        implementations
        """
        # this is what all subclasses will do anyway, so doing this here we can reduce code duplication significantly
        return bytes(self.__bytearray__())


class Field(PGPObject):
    @abc.abstractmethod
    def __len__(self):
        """Return the length of the output of __bytes__"""


class Header(Field):
    @staticmethod
    def encode_length(length, nhf=True, llen=1):
        def _new_length(nl):
            if 192 > nl:
                return Header.int_to_bytes(nl)

            elif 8384 > nl:
                elen = ((nl & 0xFF00) + (192 << 8)) + ((nl & 0xFF) - 192)
                return Header.int_to_bytes(elen, 2)

            return b'\xFF' + Header.int_to_bytes(nl, 4)

        def _old_length(nl, llen):
            return Header.int_to_bytes(nl, llen) if llen > 0 else b''

        return _new_length(length) if nhf else _old_length(length, llen)

    @sdproperty
    def length(self):
        pass

    @length.register(int)
    def length_int(self, val):
        pass

    @length.register(bytes)
    @length.register(bytearray)
    def length_bin(self, val):
        pass

    @sdproperty
    def llen(self):
        pass

    @llen.register(int)
    def llen_int(self, val):
        pass

    def __init__(self):
        super(Header, self).__init__()
        self._len = 1
        self._llen = 1
        self._lenfmt = 1
        self._partial = False


class MetaDispatchable(abc.ABCMeta):
    """
    MetaDispatchable is a metaclass for objects that subclass Dispatchable
    """

    _roots = set()
    """
    _roots is a set of all currently registered RootClass class objects

    A RootClass is successfully registered if the following things are true:
     - it inherits (directly or indirectly) from Dispatchable
     - __typeid__ == -1
    """
    _registry = {}
    """
    _registry is the Dispatchable class registry. It uses the following format:

    { (RootClass, None): OpaqueClass }:
        denotes the default ("opaque") for a given RootClass.

        An OpaqueClass is successfully registered as such provided the following conditions are met:
         - it inherits directly from a RootClass
         - __typeid__ is None

    { (RootClass, TypeID): SubClass }:
        denotes the class that handles the type given in TypeID

        a SubClass is successfully registered as such provided the following conditions are met:
         - it inherits (directly or indirectly) from a RootClass
         - __typeid__ is a positive int
         - the given typeid is not already registered

    { (RootClass, TypeID): VerSubClass }:
        denotes that a given TypeID has multiple versions, and that this is class' subclasses handle those.
        A VerSubClass is registered identically to a normal SubClass.

    { (RootClass, TypeID, Ver): VerSubClass }:
        denotes the class that handles the type given in TypeID and the version of that type given in Ver

        a Versioned SubClass is successfully registered as such provided the following conditions are met:
         - it inherits from a VerSubClass
         - __ver__ > 0
         - the given typeid/ver combination is not already registered
    """

    def __new__(mcs, name, bases, attrs):  # NOQA
        ncls = super(MetaDispatchable, mcs).__new__(mcs, name, bases, attrs)

        if not hasattr(ncls.__typeid__, '__isabstractmethod__'):
            if ncls.__typeid__ == -1 and not issubclass(ncls, tuple(MetaDispatchable._roots)):
                # this is a root class
                MetaDispatchable._roots.add(ncls)

            elif issubclass(ncls, tuple(MetaDispatchable._roots)) and ncls.__typeid__ != -1:
                for rcls in (root for root in MetaDispatchable._roots if issubclass(ncls, root)):
                    if (rcls, ncls.__typeid__) not in MetaDispatchable._registry:
                        MetaDispatchable._registry[(rcls, ncls.__typeid__)] = ncls

                    if (
                        ncls.__ver__ is not None
                        and ncls.__ver__ > 0
                        and (rcls, ncls.__typeid__, ncls.__ver__) not in MetaDispatchable._registry
                    ):
                        MetaDispatchable._registry[(rcls, ncls.__typeid__, ncls.__ver__)] = ncls

        # finally, return the new class object
        return ncls

    def __call__(cls, packet=None):  # NOQA
        def _makeobj(cls):
            pass

        if packet is not None:
            if cls in MetaDispatchable._roots:
                rcls = cls

            elif issubclass(cls, tuple(MetaDispatchable._roots)):  # pragma: no cover
                rcls = next(root for root in MetaDispatchable._roots if issubclass(cls, root))

            ##TODO: else raise an exception of some kind, but this should never happen

            header = rcls.__headercls__()
            header.parse(packet)

            ncls = None
            if (rcls, header.typeid) in MetaDispatchable._registry:
                ncls = MetaDispatchable._registry[(rcls, header.typeid)]

                if ncls.__ver__ == 0:
                    if header.__class__ != ncls.__headercls__:
                        nh = ncls.__headercls__()
                        nh.__dict__.update(header.__dict__)
                        try:
                            nh.parse(packet)

                        except Exception as ex:
                            raise PGPError(str(ex)) from ex

                        header = nh

                    if (rcls, header.typeid, header.version) in MetaDispatchable._registry:
                        ncls = MetaDispatchable._registry[(rcls, header.typeid, header.version)]

                    else:  # pragma: no cover
                        ncls = None

            if ncls is None:
                ncls = MetaDispatchable._registry[(rcls, None)]

            obj = _makeobj(ncls)
            obj.header = header

            try:
                obj.parse(packet)

            except Exception as ex:
                raise PGPError(str(ex)) from ex

        else:
            obj = _makeobj(cls)

        return obj


class Dispatchable(PGPObject, metaclass=MetaDispatchable):

    @abc.abstractproperty
    def __headercls__(self):  # pragma: no cover
        return False

    @abc.abstractproperty
    def __typeid__(self):  # pragma: no cover
        return False

    __ver__ = None


class SignatureVerification(object):
    __slots__ = ("_subjects",)
    _sigsubj = collections.namedtuple('sigsubj', ['issues', 'by', 'signature', 'subject'])

    @property
    def good_signatures(self):
        """
        A generator yielding namedtuples of all signatures that were successfully verified
        in the operation that returned this instance. The namedtuple has the following attributes:

        ``sigsubj.issues`` - ``SecurityIssues`` of whether the signature verified successfully or not. Must be 0 for success.

        ``sigsubj.by`` - the :py:obj:`~pgpy.PGPKey` that was used in this verify operation.

        ``sigsubj.signature`` - the :py:obj:`~pgpy.PGPSignature` that was verified.

        ``sigsubj.subject`` - the subject that was verified using the signature.
        """
        pass

    @property
    def bad_signatures(self):  # pragma: no cover
        """
        A generator yielding namedtuples of all signatures that were not verified
        in the operation that returned this instance. The namedtuple has the following attributes:

        ``sigsubj.verified`` - ``bool`` of whether the signature verified successfully or not.

        ``sigsubj.by`` - the :py:obj:`~pgpy.PGPKey` that was used in this verify operation.

        ``sigsubj.signature`` - the :py:obj:`~pgpy.PGPSignature` that was verified.

        ``sigsubj.subject`` - the subject that was verified using the signature.
        """
        pass

    def __init__(self):
        """
        Returned by :py:meth:`.PGPKey.verify`

        Can be compared directly as a boolean to determine whether or not the specified signature verified.
        """
        super(SignatureVerification, self).__init__()
        self._subjects = []

    def __contains__(self, item):
        return item in {ii for i in self._subjects for ii in [i.signature, i.subject]}

    def __len__(self):
        return len(self._subjects)

    def __bool__(self):
        from .constants import SecurityIssues
        return all(
            sigsub.issues is SecurityIssues.OK
            or (sigsub.issues and not sigsub.issues.causes_signature_verify_to_fail)
            for sigsub in self._subjects
        )

    def __nonzero__(self):
        return self.__bool__()

    def __and__(self, other):
        if not isinstance(other, SignatureVerification):
            raise TypeError(type(other))

        self._subjects += other._subjects
        return self

    def __repr__(self):
        return '<{classname}({val})>'.format(
            classname=self.__class__.__name__,
            val=bool(self)
        )

    def add_sigsubj(self, signature, by, subject=None, issues=None):
        pass


class FlagEnumMeta(EnumMeta):
    def __and__(self, other):
        return { f for f in iter(self) if f.value & other }

    def __rand__(self, other):  # pragma: no cover
        return self & other


namespace = FlagEnumMeta.__prepare__('FlagEnum', (IntEnum,))
FlagEnum = FlagEnumMeta('FlagEnum', (IntEnum,), namespace)


class Fingerprint(str):
    """
    A subclass of ``str``. Can be compared using == and != to ``str``, ``unicode``, and other :py:obj:`Fingerprint` instances.

    Primarily used as a key for internal dictionaries, so it ignores spaces when comparing and hashing
    """
    @property
    def keyid(self):
        pass

    @property
    def shortid(self):
        pass

    def __new__(cls, content):
        if isinstance(content, Fingerprint):
            return content

        # validate input before continuing: this should be a string of 40 hex digits
        content = content.upper().replace(' ', '')
        if not re.match(r'^[0-9A-F]+$', content):
            raise ValueError('Fingerprint must be a string of 40 hex digits')
        return str.__new__(cls, content)

    def __eq__(self, other):
        if isinstance(other, Fingerprint):
            return str(self) == str(other)

        if isinstance(other, (str, bytes, bytearray)):
            if isinstance(other, (bytes, bytearray)):  # pragma: no cover
                other = other.decode('latin-1')

            other = other.replace(' ', '')
            return any([str(self) == other,
                        self.keyid == other,
                        self.shortid == other])

        return False  # pragma: no cover

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(str(self))

    def __bytes__(self):
        return binascii.unhexlify(self.encode("latin-1"))

    def __pretty__(self):
        content = self
        if not bool(re.match(r'^[A-F0-9]{40}$', content)):
            raise ValueError("Expected: String of 40 hex digits")

        halves = [
            [content[i:i + 4] for i in range(0, 20, 4)],
            [content[i:i + 4] for i in range(20, 40, 4)]
        ]
        return '  '.join(' '.join(c for c in half) for half in halves)

    def __repr__(self):
        return '{classname}({fp})'.format(
            classname=self.__class__.__name__,
            fp=self.__pretty__()
        )


class SorteDeque(collections.deque):
    """A deque subclass that tries to maintain sorted ordering using bisect"""
    def insort(self, item):
        pass

    def resort(self, item):  # pragma: no cover
        pass

    def check(self):  # pragma: no cover
        """re-sort any items in self that are not sorted"""
        pass
