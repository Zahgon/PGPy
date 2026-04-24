""" pgp.py

this is where the armorable PGP block objects live
"""
import binascii
import collections
try:
    import collections.abc as collections_abc
except ImportError:
    collections_abc = collections
import contextlib
import copy
import functools
import itertools
import operator
import os
import re
import warnings
import weakref

from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes

from .constants import CompressionAlgorithm
from .constants import Features
from .constants import HashAlgorithm
from .constants import ImageEncoding
from .constants import KeyFlags
from .constants import NotationDataFlags
from .constants import PacketTag
from .constants import PubKeyAlgorithm
from .constants import RevocationKeyClass
from .constants import RevocationReason
from .constants import SignatureType
from .constants import SymmetricKeyAlgorithm
from .constants import SecurityIssues

from .decorators import KeyAction

from .errors import PGPDecryptionError
from .errors import PGPError

from .packet import Key
from .packet import MDC
from .packet import Packet
from .packet import Primary
from .packet import Private
from .packet import PubKeyV4
from .packet import PrivKeyV4
from .packet import PrivSubKeyV4
from .packet import Public
from .packet import Sub
from .packet import UserID
from .packet import UserAttribute

from .packet.packets import CompressedData
from .packet.packets import IntegrityProtectedSKEData
from .packet.packets import IntegrityProtectedSKEDataV1
from .packet.packets import LiteralData
from .packet.packets import OnePassSignature
from .packet.packets import OnePassSignatureV3
from .packet.packets import PKESessionKey
from .packet.packets import PKESessionKeyV3
from .packet.packets import Signature
from .packet.packets import SignatureV4
from .packet.packets import SKEData
from .packet.packets import Marker
from .packet.packets import SKESessionKey
from .packet.packets import SKESessionKeyV4

from .packet.types import Opaque

from .types import Armorable
from .types import Fingerprint
from .types import ParentRef
from .types import PGPObject
from .types import SignatureVerification
from .types import SorteDeque

__all__ = ['PGPSignature',
           'PGPUID',
           'PGPMessage',
           'PGPKey',
           'PGPKeyring']


class PGPSignature(Armorable, ParentRef, PGPObject):
    _reason_for_revocation = collections.namedtuple('ReasonForRevocation', ['code', 'comment'])

    @property
    def __sig__(self):
        return self._signature.signature.__sig__()

    @property
    def cipherprefs(self):
        """
        A ``list`` of preferred symmetric algorithms specified in this signature, if any. Otherwise, an empty ``list``.
        """
        pass

    @property
    def compprefs(self):
        """
        A ``list`` of preferred compression algorithms specified in this signature, if any. Otherwise, an empty ``list``.
        """
        pass

    @property
    def created(self):
        """
        A :py:obj:`~datetime.datetime` of when this signature was created.
        """
        pass

    @property
    def embedded(self):
        pass

    @property
    def expires_at(self):
        """
        A :py:obj:`~datetime.datetime` of when this signature expires, if a signature expiration date is specified.
        Otherwise, ``None``
        """
        pass

    @property
    def exportable(self):
        """
        ``False`` if this signature is marked as being not exportable. Otherwise, ``True``.
        """
        pass

    @property
    def features(self):
        """
        A ``set`` of implementation features specified in this signature, if any. Otherwise, an empty ``set``.
        """
        pass

    @property
    def hash2(self):
        pass

    @property
    def hashprefs(self):
        """
        A ``list`` of preferred hash algorithms specified in this signature, if any. Otherwise, an empty ``list``.
        """
        pass

    @property
    def hash_algorithm(self):
        """
        The :py:obj:`~constants.HashAlgorithm` used when computing this signature.
        """
        pass

    def check_primitives(self):
        pass

    def check_soundness(self):
        pass

    @property
    def is_expired(self):
        """
        ``True`` if the signature has an expiration date, and is expired. Otherwise, ``False``
        """
        pass

    @property
    def key_algorithm(self):
        """
        The :py:obj:`~constants.PubKeyAlgorithm` of the key that generated this signature.
        """
        pass

    @property
    def key_expiration(self):
        pass

    @property
    def key_flags(self):
        """
        A ``set`` of :py:obj:`~constants.KeyFlags` specified in this signature, if any. Otherwise, an empty ``set``.
        """
        pass

    @property
    def keyserver(self):
        """
        The preferred key server specified in this signature, if any. Otherwise, an empty ``str``.
        """
        pass

    @property
    def keyserverprefs(self):
        """
        A ``list`` of :py:obj:`~constants.KeyServerPreferences` in this signature, if any. Otherwise, an empty ``list``.
        """
        pass

    @property
    def magic(self):
        pass

    @property
    def notation(self):
        """
        A ``dict`` of notation data in this signature, if any. Otherwise, an empty ``dict``.
        """
        pass

    @property
    def policy_uri(self):
        """
        The policy URI specified in this signature, if any. Otherwise, an empty ``str``.
        """
        pass

    @property
    def revocable(self):
        """
        ``False`` if this signature is marked as being not revocable. Otherwise, ``True``.
        """
        pass

    @property
    def revocation_key(self):
        pass

    @property
    def revocation_reason(self):
        pass

    @property
    def attested_certifications(self):
        """
        Returns a set of all the hashes of attested certifications covered by this Attestation Key Signature.

        Unhashed subpackets are ignored.
        """
        pass

    @property
    def signer(self):
        """
        The 16-character Key ID of the key that generated this signature.
        """
        pass

    @property
    def signer_fingerprint(self):
        """
        The fingerprint of the key that generated this signature, if it contained. Otherwise, an empty ``str``.
        """
        pass

    @property
    def intended_recipients(self):
        """
        Returns an iterator over all the primary key fingerprints marked as intended encrypted recipients for this signature.
        """
        pass

    @property
    def target_signature(self):
        pass

    @property
    def type(self):
        """
        The :py:obj:`~constants.SignatureType` of this signature.
        """
        pass

    @classmethod
    def new(cls, sigtype, pkalg, halg, signer, created=None):
        sig = PGPSignature()

        if created is None:
            created = datetime.now(timezone.utc)
        sigpkt = SignatureV4()
        sigpkt.header.tag = 2
        sigpkt.header.version = 4
        sigpkt.subpackets.addnew('CreationTime', hashed=True, created=created)
        sigpkt.subpackets.addnew('Issuer', _issuer=signer)

        sigpkt.sigtype = sigtype
        sigpkt.pubalg = pkalg

        if halg is not None:
            sigpkt.halg = halg

        sig._signature = sigpkt
        return sig

    def __init__(self):
        """
        PGPSignature objects represent OpenPGP compliant signatures.

        PGPSignature implements the ``__str__`` method, the output of which will be the signature object in
        OpenPGP-compliant ASCII-armored format.

        PGPSignature implements the ``__bytes__`` method, the output of which will be the signature object in
        OpenPGP-compliant binary format.
        """
        super(PGPSignature, self).__init__()
        self._signature = None

    def __bytearray__(self):
        return self._signature.__bytearray__()

    def __repr__(self):
        return "<PGPSignature [{:s}] object at 0x{:02x}>".format(self.type.name, id(self))

    def __lt__(self, other):
        return self.created < other.created

    def __or__(self, other):
        if isinstance(other, Signature):
            if self._signature is None:
                self._signature = other
                return self

        ##TODO: this is not a great way to do this
        if other.__class__.__name__ == 'EmbeddedSignature':
            self._signature = other
            return self

        raise TypeError

    def __copy__(self):
        # because the default shallow copy isn't actually all that useful,
        # and deepcopy does too much work
        sig = super(PGPSignature, self).__copy__()
        # sig = PGPSignature()
        # sig.ascii_headers = self.ascii_headers.copy()
        sig |= copy.copy(self._signature)
        return sig

    def attests_to(self, othersig):
        'returns True if this signature attests to othersig (acknolwedges it for redistribution)'
        pass

    def hashdata(self, subject):
        pass

    def make_onepass(self):
        pass

    def parse(self, packet):
        unarmored = self.ascii_unarmor(packet)
        data = unarmored['body']

        if unarmored['magic'] is not None and unarmored['magic'] != 'SIGNATURE':
            raise ValueError('Expected: SIGNATURE. Got: {}'.format(str(unarmored['magic'])))

        if unarmored['headers'] is not None:
            self.ascii_headers = unarmored['headers']

        # load *one* packet from data
        pkt = Packet(data)
        if pkt.header.tag == PacketTag.Signature:
            if isinstance(pkt, Opaque):
                # this is an unrecognized version.
                pass
            else:
                self._signature = pkt
        else:
            raise ValueError('Expected: Signature. Got: {:s}'.format(pkt.__class__.__name__))


class PGPUID(ParentRef):
    @property
    def __sig__(self):
        return list(self._signatures)

    def _splitstring(self):
        '''returns name, comment email from User ID string'''
        pass

    @property
    def name(self):
        """If this is a User ID, the stored name. If this is not a User ID, this will be an empty string."""
        pass

    @property
    def comment(self):
        """
        If this is a User ID, this will be the stored comment. If this is not a User ID, or there is no stored comment,
        this will be an empty string.,
        """
        pass

    @property
    def email(self):
        """
        If this is a User ID, this will be the stored email address. If this is not a User ID, or there is no stored
        email address, this will be an empty string.
        """
        pass

    @property
    def userid(self):
        """
        If this is a User ID, this will be the full UTF-8 string. If this is not a User ID, this will be ``None``.
        """
        pass

    @property
    def image(self):
        """
        If this is a User Attribute, this will be the stored image. If this is not a User Attribute, this will be ``None``.
        """
        pass

    @property
    def is_primary(self):
        """
        If the most recent, valid self-signature specifies this as being primary, this will be True. Otherwise, False.
        """
        pass

    @property
    def is_uid(self):
        """
        ``True`` if this is a User ID, otherwise False.
        """
        pass

    @property
    def is_ua(self):
        """
        ``True`` if this is a User Attribute, otherwise False.
        """
        pass

    @property
    def selfsig(self):
        """
        This will be the most recent, self-signature of this User ID or Attribute. If there isn't one, this will be ``None``.
        """
        pass

    @property
    def signers(self):
        """
        This will be a set of all of the key ids which have signed this User ID or Attribute.
        """
        pass

    @property
    def hashdata(self):
        pass

    @property
    def third_party_certifications(self):
        '''
        A generator returning all third-party certifications
        '''
        pass

    def attested_to(self, certifications):
        '''filter certifications, only returning those that have been attested to by the first party'''
        pass

    @property
    def attested_third_party_certifications(self):
        '''
        A generator that provides a list of all third-party certifications attested to
        by the primary key.
        '''
        pass

    @classmethod
    def new(cls, pn, comment="", email=""):
        """
        Create a new User ID or photo.

        :param pn: User ID name, or photo. If this is a ``bytearray``, it will be loaded as a photo.
                   Otherwise, it will be used as the name field for a User ID.
        :type pn: ``bytearray``, ``str``, ``unicode``
        :param comment: The comment field for a User ID. Ignored if this is a photo.
        :type comment: ``str``, ``unicode``
        :param email: The email address field for a User ID. Ignored if this is a photo.
        :type email: ``str``, ``unicode``
        :returns: :py:obj:`PGPUID`
        """
        uid = PGPUID()
        if isinstance(pn, bytearray):
            uid._uid = UserAttribute()
            uid._uid.image.image = pn
            uid._uid.image.iencoding = ImageEncoding.encodingof(pn)
            uid._uid.update_hlen()

        else:
            uid._uid = UserID()
            uidstr = pn
            if comment:
                uidstr += ' (' + comment + ')'
            if email:
                uidstr += ' <' + email + '>'
            uid._uid.uid = uidstr
            uid._uid.update_hlen()

        return uid

    def __init__(self):
        """
        PGPUID objects represent User IDs and User Attributes for keys.

        PGPUID implements the ``__format__`` method for User IDs, returning a string in the format
        'name (comment) <email>', leaving out any comment or email fields that are not present.
        """
        super(PGPUID, self).__init__()
        self._uid = None
        self._signatures = SorteDeque()

    def __repr__(self):
        if self.selfsig is not None:
            return "<PGPUID [{:s}][{}] at 0x{:02X}>".format(self._uid.__class__.__name__, self.selfsig.created, id(self))
        return "<PGPUID [{:s}] at 0x{:02X}>".format(self._uid.__class__.__name__, id(self))

    def __lt__(self, other):  # pragma: no cover
        if self.is_uid == other.is_uid:
            if self.is_primary == other.is_primary:
                mysig = self.selfsig
                othersig = other.selfsig
                if mysig is None:
                    return not (othersig is None)
                if othersig is None:
                    return False
                return mysig > othersig

            if self.is_primary:
                return True

            return False

        if self.is_uid and other.is_ua:
            return True

        if self.is_ua and other.is_uid:
            return False

    def __or__(self, other):
        if isinstance(other, PGPSignature):
            self._signatures.insort(other)
            if self.parent is not None and self in self.parent._uids:
                self.parent._uids.resort(self)

            return self

        if isinstance(other, UserID) and self._uid is None:
            self._uid = other
            return self

        if isinstance(other, UserAttribute) and self._uid is None:
            self._uid = other
            return self

        raise TypeError("unsupported operand type(s) for |: '{:s}' and '{:s}'"
                        "".format(self.__class__.__name__, other.__class__.__name__))

    def __copy__(self):
        # because the default shallow copy isn't actually all that useful,
        # and deepcopy does too much work
        uid = PGPUID()
        uid |= copy.copy(self._uid)
        for sig in self._signatures:
            uid |= copy.copy(sig)
        return uid

    def __format__(self, format_spec):
        if self.is_uid:
            comment = "" if self.comment == "" else " ({:s})".format(self.comment)
            email = "" if self.email == "" else " <{:s}>".format(self.email)
            return "{:s}{:s}{:s}".format(self.name, comment, email)

        raise NotImplementedError


class PGPMessage(Armorable, PGPObject):
    @staticmethod
    def dash_unescape(text):
        return re.subn(r'^- ', '', text, flags=re.MULTILINE)[0]

    @staticmethod
    def dash_escape(text):
        pass

    @property
    def encrypters(self):
        """A ``set`` containing all key ids (if any) to which this message was encrypted."""
        pass

    @property
    def filename(self):
        """If applicable, returns the original filename of the message. Otherwise, returns an empty string."""
        pass

    @property
    def is_compressed(self):
        """``True`` if this message will be compressed when exported"""
        pass

    @property
    def is_encrypted(self):
        """``True`` if this message is encrypted; otherwise, ``False``"""
        pass

    @property
    def is_sensitive(self):
        """``True`` if this message is marked sensitive; otherwise ``False``"""
        pass

    @property
    def is_signed(self):
        """
        ``True`` if this message is signed; otherwise, ``False``.
        Should always be ``False`` if the message is encrypted.
        """
        pass

    @property
    def issuers(self):
        """A ``set`` containing all key ids (if any) which have signed or encrypted this message."""
        pass

    @property
    def magic(self):
        pass

    @property
    def message(self):
        """The message contents"""
        pass

    @property
    def signatures(self):
        """A ``set`` containing all key ids (if any) which have signed this message."""
        pass

    @property
    def signers(self):
        """A ``set`` containing all key ids (if any) which have signed this message."""
        pass

    @property
    def type(self):
        ##TODO: it might be better to use an Enum for the output of this
        pass

    def __init__(self):
        """
        PGPMessage objects represent OpenPGP message compositions.

        PGPMessage implements the ``__str__`` method, the output of which will be the message composition in
        OpenPGP-compliant ASCII-armored format.

        PGPMessage implements the ``__bytes__`` method, the output of which will be the message composition in
        OpenPGP-compliant binary format.

        Any signatures within the PGPMessage that are marked as being non-exportable will not be included in the output
        of either of those methods.
        """
        super(PGPMessage, self).__init__()
        self._compression = CompressionAlgorithm.Uncompressed
        self._message = None
        self._mdc = None
        self._signatures = SorteDeque()
        self._sessionkeys = []

    def __bytearray__(self):
        if self.is_compressed:
            comp = CompressedData()
            comp.calg = self._compression
            comp.packets = [pkt for pkt in self]
            comp.update_hlen()
            return comp.__bytearray__()

        _bytes = bytearray()
        for pkt in self:
            _bytes += pkt.__bytearray__()
        return _bytes

    def __str__(self):
        if self.type == 'cleartext':
            tmpl = u"-----BEGIN PGP SIGNED MESSAGE-----\n" \
                   u"{hhdr:s}\n" \
                   u"{cleartext:s}\n" \
                   u"{signature:s}"

            # only add a Hash: header if we actually have at least one signature
            hashes = set(s.hash_algorithm.name for s in self.signatures)
            hhdr = 'Hash: {hashes:s}\n'.format(hashes=','.join(sorted(hashes))) if hashes else ''

            return tmpl.format(hhdr=hhdr,
                               cleartext=self.dash_escape(self.bytes_to_text(self._message)),
                               signature=super(PGPMessage, self).__str__())

        return super(PGPMessage, self).__str__()

    def __iter__(self):
        if self.type == 'cleartext':
            for sig in self._signatures:
                yield sig

        elif self.is_encrypted:
            for sig in self._signatures:
                yield sig
            for pkt in self._sessionkeys:
                yield pkt
            yield self.message

        else:
            ##TODO: is it worth coming up with a way of disabling one-pass signing?
            for sig in reversed(self._signatures):
                ops = sig.make_onepass()
                if sig is not self._signatures[-1]:
                    ops.nested = True
                yield ops

            yield self._message
            if self._mdc is not None:  # pragma: no cover
                yield self._mdc

            for sig in self._signatures:
                yield sig

    def __or__(self, other):
        if isinstance(other, Marker):
            return self

        if isinstance(other, CompressedData):
            self._compression = other.calg
            for pkt in other.packets:
                self |= pkt
            return self

        if isinstance(other, (str, bytes, bytearray)):
            if self._message is None:
                self._message = self.text_to_bytes(other)
                return self

        if isinstance(other, (LiteralData, SKEData, IntegrityProtectedSKEData)):
            if self._message is None:
                self._message = other
                return self

        if isinstance(other, MDC):
            if self._mdc is None:
                self._mdc = other
                return self

        if isinstance(other, OnePassSignature):
            # these are "generated" on the fly during composition
            return self

        if isinstance(other, Signature):
            other = PGPSignature() | other

        if isinstance(other, PGPSignature):
            self._signatures.insort(other)
            return self

        if isinstance(other, (PKESessionKey, SKESessionKey)):
            self._sessionkeys.append(other)
            return self

        if isinstance(other, PGPMessage):
            self._message = other._message
            self._mdc = other._mdc
            self._compression = other._compression
            self._sessionkeys += other._sessionkeys
            self._signatures += other._signatures
            return self

        raise NotImplementedError(str(type(other)))

    def __copy__(self):
        msg = super(PGPMessage, self).__copy__()
        msg._compression = self._compression
        msg._message = copy.copy(self._message)
        msg._mdc = copy.copy(self._mdc)

        for sig in self._signatures:
            msg |= copy.copy(sig)

        for sk in self._sessionkeys:
            msg |= copy.copy(sk)

        return msg

    @classmethod
    def new(cls, message, **kwargs):
        """
        Create a new PGPMessage object.

        :param message: The message to be stored.
        :type message: ``str``, ``unicode``, ``bytes``, ``bytearray``
        :returns: :py:obj:`PGPMessage`

        The following optional keyword arguments can be used with :py:meth:`PGPMessage.new`:

        :keyword file: if True, ``message`` should be a path to a file. The contents of that file will be read and used
                       as the contents of the message.
        :type file: ``bool``
        :keyword cleartext: if True, the message will be cleartext with inline signatures.
        :type cleartext: ``bool``
        :keyword sensitive: if True, the filename will be set to '_CONSOLE' to signal other OpenPGP clients to treat
                            this message as being 'for your eyes only'. Ignored if cleartext is True.
        :type sensitive: ``bool``
        :keyword format: Set the message format identifier. Ignored if cleartext is True.
        :type format: ``str``
        :keyword compression: Set the compression algorithm for the new message.
                              Defaults to :py:obj:`CompressionAlgorithm.ZIP`. Ignored if cleartext is True.
        :keyword encoding: Set the Charset header for the message.
        :type encoding: ``str`` representing a valid codec in codecs
        """
        # TODO: have 'codecs' above (in :type encoding:) link to python documentation page on codecs
        cleartext = kwargs.pop('cleartext', False)
        format = kwargs.pop('format', None)
        sensitive = kwargs.pop('sensitive', False)
        compression = kwargs.pop('compression', CompressionAlgorithm.ZIP)
        file = kwargs.pop('file', False)
        charset = kwargs.pop('encoding', None)

        filename = ''
        mtime = datetime.now(timezone.utc)

        msg = PGPMessage()

        if charset:
            msg.charset = charset

        # if format in 'tu' and isinstance(message, (bytes, bytearray)):
        #     # if message format is text or unicode and we got binary data, we'll need to transcode it to UTF-8
        #     message =

        if file and os.path.isfile(message):
            filename = message
            message = bytearray(os.path.getsize(filename))
            mtime = datetime.fromtimestamp(os.path.getmtime(filename), timezone.utc)

            with open(filename, 'rb') as mf:
                mf.readinto(message)

        # if format is None, we can try to detect it
        if format is None:
            if isinstance(message, str):
                # message is definitely UTF-8 already
                format = 'u'

            elif cls.is_ascii(message):
                # message is probably text
                format = 't'

            else:
                # message is probably binary
                format = 'b'

        # if message is a binary type and we're building a textual message, we need to transcode the bytes to UTF-8
        if isinstance(message, (bytes, bytearray)) and (cleartext or format in 'tu'):
            message = message.decode(charset or 'utf-8')

        if cleartext:
            msg |= message

        else:
            # load literal data
            lit = LiteralData()
            lit._contents = bytearray(msg.text_to_bytes(message))
            lit.filename = '_CONSOLE' if sensitive else os.path.basename(filename)
            lit.mtime = mtime
            lit.format = format

            # if cls.is_ascii(message):
            #     lit.format = 't'

            lit.update_hlen()

            msg |= lit
            msg._compression = compression

        return msg

    def encrypt(self, passphrase, sessionkey=None, **prefs):
        """
        encrypt(passphrase, [sessionkey=None,] **prefs)

        Encrypt the contents of this message using a passphrase.

        :param passphrase: The passphrase to use for encrypting this message.
        :type passphrase: ``str``, ``unicode``, ``bytes``

        :param sessionkey: Provide a session key to use when encrypting something. Default is ``None``.
                                    If ``None``, a session key of the appropriate length will be generated randomly.

                                    .. warning::

                                        Care should be taken when making use of this option! Session keys *absolutely need*
                                        to be unpredictable! Use the ``gen_key()`` method on the desired
                                        :py:obj:`~constants.SymmetricKeyAlgorithm` to generate the session key!

        :type sessionkey: ``bytes``, ``str``
        :raises: :py:exc:`~errors.PGPEncryptionError`
        :returns: A new :py:obj:`PGPMessage` containing the encrypted contents of this message.
        """
        pass

    def decrypt(self, passphrase):
        """
        Attempt to decrypt this message using a passphrase.

        :param passphrase: The passphrase to use to attempt to decrypt this message.
        :type passphrase: ``str``, ``unicode``, ``bytes``
        :raises: :py:exc:`~errors.PGPDecryptionError` if decryption failed for any reason.
        :returns: A new :py:obj:`PGPMessage` containing the decrypted contents of this message
        """
        pass

    def parse(self, packet):
        unarmored = self.ascii_unarmor(packet)
        data = unarmored['body']

        if unarmored['magic'] is not None and unarmored['magic'] not in ['MESSAGE', 'SIGNATURE']:
            raise ValueError('Expected: MESSAGE. Got: {}'.format(str(unarmored['magic'])))

        if unarmored['headers'] is not None:
            self.ascii_headers = unarmored['headers']

        # cleartext signature
        if unarmored['magic'] == 'SIGNATURE':
            # the composition for this will be the 'cleartext' as a str,
            # followed by one or more signatures (each one loaded into a PGPSignature)
            self |= self.dash_unescape(unarmored['cleartext'])
            while len(data) > 0:
                pkt = Packet(data)
                if not isinstance(pkt, Signature):  # pragma: no cover
                    warnings.warn("Discarded unexpected packet: {:s}".format(pkt.__class__.__name__), stacklevel=2)
                    continue
                self |= PGPSignature() | pkt

        else:
            while len(data) > 0:
                self |= Packet(data)


class PGPKey(Armorable, ParentRef, PGPObject):
    """
    11.1.  Transferable Public Keys

    OpenPGP users may transfer public keys.  The essential elements of a
    transferable public key are as follows:

     - One Public-Key packet

     - Zero or more revocation signatures
     - One or more User ID packets

     - After each User ID packet, zero or more Signature packets
       (certifications)

     - Zero or more User Attribute packets

     - After each User Attribute packet, zero or more Signature packets
       (certifications)

     - Zero or more Subkey packets

     - After each Subkey packet, one Signature packet, plus optionally a
       revocation

    The Public-Key packet occurs first.  Each of the following User ID
    packets provides the identity of the owner of this public key.  If
    there are multiple User ID packets, this corresponds to multiple
    means of identifying the same unique individual user; for example, a
    user may have more than one email address, and construct a User ID
    for each one.

    Immediately following each User ID packet, there are zero or more
    Signature packets.  Each Signature packet is calculated on the
    immediately preceding User ID packet and the initial Public-Key
    packet.  The signature serves to certify the corresponding public key
    and User ID.  In effect, the signer is testifying to his or her
    belief that this public key belongs to the user identified by this
    User ID.

    Within the same section as the User ID packets, there are zero or
    more User Attribute packets.  Like the User ID packets, a User
    Attribute packet is followed by zero or more Signature packets
    calculated on the immediately preceding User Attribute packet and the
    initial Public-Key packet.

    User Attribute packets and User ID packets may be freely intermixed
    in this section, so long as the signatures that follow them are
    maintained on the proper User Attribute or User ID packet.

    After the User ID packet or Attribute packet, there may be zero or
    more Subkey packets.  In general, subkeys are provided in cases where
    the top-level public key is a signature-only key.  However, any V4
    key may have subkeys, and the subkeys may be encryption-only keys,
    signature-only keys, or general-purpose keys.  V3 keys MUST NOT have
    subkeys.

    Each Subkey packet MUST be followed by one Signature packet, which
    should be a subkey binding signature issued by the top-level key.
    For subkeys that can issue signatures, the subkey binding signature
    MUST contain an Embedded Signature subpacket with a primary key
    binding signature (0x19) issued by the subkey on the top-level key.

    Subkey and Key packets may each be followed by a revocation Signature
    packet to indicate that the key is revoked.  Revocation signatures
    are only accepted if they are issued by the key itself, or by a key
    that is authorized to issue revocations via a Revocation Key
    subpacket in a self-signature by the top-level key.

    Transferable public-key packet sequences may be concatenated to allow
    transferring multiple public keys in one operation.

    11.2.  Transferable Secret Keys

    OpenPGP users may transfer secret keys.  The format of a transferable
    secret key is the same as a transferable public key except that
    secret-key and secret-subkey packets are used instead of the public
    key and public-subkey packets.  Implementations SHOULD include self-
    signatures on any user IDs and subkeys, as this allows for a complete
    public key to be automatically extracted from the transferable secret
    key.  Implementations MAY choose to omit the self-signatures,
    especially if a transferable public key accompanies the transferable
    secret key.
    """
    @property
    def __key__(self):
        return self._key.keymaterial

    @property
    def __sig__(self):
        return list(self._signatures)

    @property
    def created(self):
        """A :py:obj:`~datetime.datetime` object of the creation date and time of the key, in UTC."""
        pass

    @property
    def expires_at(self):
        """A :py:obj:`~datetime.datetime` object of when this key is to be considered expired, if any. Otherwise, ``None``"""
        pass

    @property
    def fingerprint(self):
        """The fingerprint of this key, as a :py:obj:`~pgpy.types.Fingerprint` object."""
        pass

    @property
    def hashdata(self):
        # when signing a key, only the public portion of the keys is hashed
        # if this is a private key, the private components of the key material need to be left out
        pass

    @property
    def is_expired(self):
        """``True`` if this key is expired, otherwise ``False``"""
        pass

    @property
    def is_primary(self):
        """``True`` if this is a primary key; ``False`` if this is a subkey"""
        pass

    @property
    def is_protected(self):
        """``True`` if this is a private key that is protected with a passphrase, otherwise ``False``"""
        pass

    @property
    def is_public(self):
        """``True`` if this is a public key, otherwise ``False``"""
        pass

    @property
    def is_unlocked(self):
        """``False`` if this is a private key that is protected with a passphrase and has not yet been unlocked, otherwise ``True``"""
        pass

    @property
    def key_algorithm(self):
        """The :py:obj:`constants.PubKeyAlgorithm` pertaining to this key"""
        pass

    @property
    def key_size(self):
        """
        The size pertaining to this key. ``int`` for non-EC key algorithms; :py:obj:`constants.EllipticCurveOID` for EC keys.

        .. versionadded:: 0.4.1
        """
        pass

    @property
    def magic(self):
        pass

    @property
    def pubkey(self):
        """If the :py:obj:`PGPKey` object is a private key, this method returns a corresponding public key object with
        all the trimmings. If it is already a public key, just return it.
        """
        pass

    @pubkey.setter
    def pubkey(self, pubkey):
        pass

    @property
    def self_signatures(self):
        pass

    @property
    def signers(self):
        """A ``set`` of key ids of keys that were used to sign this key"""
        pass

    @property
    def revocation_signatures(self):
        pass

    @property
    def subkeys(self):
        """An :py:obj:`~collections.OrderedDict` of subkeys bound to this primary key, if applicable,
        selected by 16-character keyid."""
        pass

    @property
    def userids(self):
        """A ``list`` of :py:obj:`PGPUID` objects containing User ID information about this key"""
        pass

    @property
    def userattributes(self):
        """A ``list`` of :py:obj:`PGPUID` objects containing one or more images associated with this key"""
        pass

    @property
    def revocation_keys(self):
        """A ``generator`` with the list of keys that can revoke this key.

        See also :py:func:`PGPSignature.revocation_key`"""
        pass

    @classmethod
    def new(cls, key_algorithm, key_size, created=None):
        """
        Generate a new PGP key

        :param key_algorithm: Key algorithm to use.
        :type key_algorithm: :py:obj:`~constants.PubKeyAlgorithm`
        :param key_size: Key size in bits, unless `key_algorithm` is :py:obj:`~constants.PubKeyAlgorithm.ECDSA` or
               :py:obj:`~constants.PubKeyAlgorithm.ECDH`, in which case it should be the Curve OID to use.
        :type key_size: ``int`` or :py:obj:`~constants.EllipticCurveOID`

        :param created: When was the key created? (``None`` or unset means now)
        :type created: :py:obj:`~datetime.datetime` or ``None``
        :return: A newly generated :py:obj:`PGPKey`
        """
        # new private key shell first
        key = PGPKey()

        if key_algorithm in {PubKeyAlgorithm.RSAEncrypt, PubKeyAlgorithm.RSASign}:  # pragma: no cover
            warnings.warn('{:s} is deprecated - generating key using RSAEncryptOrSign'.format(key_algorithm.name))
            key_algorithm = PubKeyAlgorithm.RSAEncryptOrSign

        # generate some key data to match key_algorithm and key_size
        key._key = PrivKeyV4.new(key_algorithm, key_size, created=created)

        return key

    def __init__(self):
        """
        PGPKey objects represent OpenPGP compliant keys along with all of their associated data.

        PGPKey implements the `__str__` method, the output of which will be the key composition in
        OpenPGP-compliant ASCII-armored format.

        PGPKey implements the `__bytes__` method, the output of which will be the key composition in
        OpenPGP-compliant binary format.

        Any signatures within the PGPKey that are marked as being non-exportable will not be included in the output
        of either of those methods.
        """
        super(PGPKey, self).__init__()
        self._key = None
        self._children = collections.OrderedDict()
        self._signatures = SorteDeque()
        self._uids = SorteDeque()
        self._sibling = None
        self._self_verified = None
        self._require_usage_flags = True

    def __bytearray__(self):
        _bytes = bytearray()
        # us
        _bytes += self._key.__bytearray__()
        # our signatures; ignore embedded signatures
        for sig in iter(s for s in self._signatures if not s.embedded and s.exportable):
            _bytes += sig.__bytearray__()
        # one or more User IDs, followed by their signatures
        for uid in self._uids:
            _bytes += uid._uid.__bytearray__()
            for s in [s for s in uid._signatures if s.exportable]:
                _bytes += s.__bytearray__()
        # subkeys
        for sk in self._children.values():
            _bytes += sk.__bytearray__()

        return _bytes

    def __repr__(self):
        if self._key is not None:
            return "<PGPKey [{:s}][0x{:s}] at 0x{:02X}>" \
                   "".format(self._key.__class__.__name__, self.fingerprint.keyid, id(self))

        return "<PGPKey [unknown] at 0x{:02X}>" \
               "".format(id(self))

    def __contains__(self, item):
        if isinstance(item, PGPKey):  # pragma: no cover
            return item.fingerprint.keyid in self.subkeys

        if isinstance(item, Fingerprint):  # pragma: no cover
            return item.keyid in self.subkeys

        if isinstance(item, PGPUID):
            return item in self._uids

        if isinstance(item, PGPSignature):
            return item in self._signatures

        raise TypeError

    def __or__(self, other, from_sib=False):
        if isinstance(other, Key) and self._key is None:
            self._key = other

        elif isinstance(other, PGPKey) and not other.is_primary and other.is_public == self.is_public:
            other._parent = self
            self._children[other.fingerprint.keyid] = other

        elif isinstance(other, PGPSignature):
            self._signatures.insort(other)

            # if this is a subkey binding signature that has embedded primary key binding signatures, add them to parent
            if other.type == SignatureType.Subkey_Binding:
                for es in iter(pkb for pkb in other._signature.subpackets['EmbeddedSignature']):
                    esig = PGPSignature() | es
                    esig._parent = other
                    self._signatures.insort(esig)

        elif isinstance(other, PGPUID):
            other._parent = weakref.ref(self)
            self._uids.insort(other)

        else:
            raise TypeError(
                "unsupported operand type(s) for |: '{:s}' and '{:s}'"
                "".format(self.__class__.__name__, other.__class__.__name__)
            )

        if isinstance(self._sibling, weakref.ref) and not from_sib:
            sib = self._sibling()
            if sib is None:
                self._sibling = None

            else:  # pragma: no cover
                sib.__or__(copy.copy(other), True)

        return self

    def __copy__(self):
        key = super(PGPKey, self).__copy__()
        key._key = copy.copy(self._key)

        for uid in self._uids:
            key |= copy.copy(uid)

        for id, subkey in self._children.items():
            key |= copy.copy(subkey)

        for sig in self._signatures:
            if sig.embedded:
                # embedded signatures don't need to be explicitly copied
                continue

            key |= copy.copy(sig)

        return key

    def protect(self, passphrase, enc_alg, hash_alg):
        """
        Add a passphrase to a private key. If the key is already passphrase protected, it should be unlocked before
        a new passphrase can be specified.

        Has no effect on public keys.

        :param passphrase: A passphrase to protect the key with
        :type passphrase: ``str``, ``unicode``
        :param enc_alg: Symmetric encryption algorithm to use to protect the key
        :type enc_alg: :py:obj:`~constants.SymmetricKeyAlgorithm`
        :param hash_alg: Hash algorithm to use in the String-to-Key specifier
        :type hash_alg: :py:obj:`~constants.HashAlgorithm`
        """
        pass

    @contextlib.contextmanager
    def unlock(self, passphrase):
        """
        Context manager method for unlocking passphrase-protected private keys. Has no effect if the key is not both
        private and passphrase-protected.

        When the context managed block is exited, the unprotected private key material is removed.

        Example::

            privkey = PGPKey()
            privkey.parse(keytext)

            assert privkey.is_protected
            assert privkey.is_unlocked is False
            # privkey.sign("some text") <- this would raise an exception

            with privkey.unlock("TheCorrectPassphrase"):
                # privkey is now unlocked
                assert privkey.is_unlocked
                # so you can do things with it
                sig = privkey.sign("some text")

            # privkey is no longer unlocked
            assert privkey.is_unlocked is False

        Emits a :py:obj:`~warnings.UserWarning` if the key is public or not passphrase protected.

        :param passphrase: The passphrase to be used to unlock this key.
        :type passphrase: ``str``
        :raises: :py:exc:`~pgpy.errors.PGPDecryptionError` if the passphrase is incorrect
        """
        pass

    def add_uid(self, uid, selfsign=True, **prefs):
        """
        Add a User ID to this key.

        :param uid: The user id to add
        :type uid: :py:obj:`~pgpy.PGPUID`
        :param selfsign: Whether or not to self-sign the user id before adding it
        :type selfsign: ``bool``

        Valid optional keyword arguments are identical to those of self-signatures for :py:meth:`PGPKey.certify`.
        Any such keyword arguments are ignored if selfsign is ``False``
        """
        pass

    def get_uid(self, search):
        """
        Find and return a User ID that matches the search string given.

        :param search: A text string to match name, comment, or email address against
        :type search: ``str``, ``unicode``
        :return: The first matching :py:obj:`~pgpy.PGPUID`, or ``None`` if no matches were found.
        """
        pass

    def del_uid(self, search):
        """
        Find and remove a user id that matches the search string given. This method does not modify the corresponding
        :py:obj:`~pgpy.PGPUID` object; it only removes it from the list of user ids on the key.

        :param search: A text string to match name, comment, or email address against
        :type search: ``str``, ``unicode``
        """
        pass

    def add_subkey(self, key, **prefs):
        """
        Add a key as a subkey to this key.

        :param key: A private :py:obj:`~pgpy.PGPKey` that does not have any subkeys of its own
        :keyword usage: A ``set`` of key usage flags, as :py:obj:`~constants.KeyFlags` for the subkey to be added.
        :type usage: ``set``

        Other valid optional keyword arguments are identical to those of self-signatures for :py:meth:`PGPKey.certify`
        """
        pass

    def _get_key_flags(self, user=None):
        pass

    def _sign(self, subject, sig, **prefs):
        """
        The actual signing magic happens here.
        :param subject: The subject to sign
        :param sig: The :py:obj:`PGPSignature` object the new signature is to be encapsulated within
        :returns: ``sig``, after the signature is added to it.
        """
        pass

    @KeyAction(KeyFlags.Sign, is_unlocked=True, is_public=False)
    def sign(self, subject, **prefs):
        """
        Sign text, a message, or a timestamp using this key.

        :param subject: The text to be signed
        :type subject: ``str``, :py:obj:`~pgpy.PGPMessage`, ``None``
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
        :returns: :py:obj:`PGPSignature`

        The following optional keyword arguments can be used with :py:meth:`PGPKey.sign`, as well as
        :py:meth:`PGPKey.certify`,  :py:meth:`PGPKey.revoke`, and :py:meth:`PGPKey.bind`:

        :keyword expires: Set an expiration date for this signature
        :type expires: :py:obj:`~datetime.datetime`, :py:obj:`~datetime.timedelta`
        :keyword notation: Add arbitrary notation data to this signature.
        :type notation: ``dict``
        :keyword policy_uri: Add a URI to the signature that should describe the policy under which the signature
                             was issued.
        :type policy_uri: ``str``
        :keyword revocable: If ``False``, this signature will be marked non-revocable
        :type revocable: ``bool``
        :keyword user: Specify which User ID to use when creating this signature. Also adds a "Signer's User ID"
                       to the signature.
        :type user: ``str``
        :keyword created: Specify the time that the signature should be made.  If unset or None,
                          it will use the present time.
        :type created: :py:obj:`~datetime.datetime`
        :keyword intended_recipients: Specify a list of :py:obj:`PGPKey` objects that will be encrypted to.
        :type intended_recipients: ``list``
        :keyword include_issuer_fingerprint: Whether to include a hashed subpacket indicating the issuer fingerprint.
                                             (only for v4 keys, defaults to True)
        :type include_issuer_fingerprint: ``bool``
        """
        pass

    @KeyAction(KeyFlags.Certify, is_unlocked=True, is_public=False)
    def certify(self, subject, level=SignatureType.Generic_Cert, **prefs):
        """
        certify(subject, level=SignatureType.Generic_Cert, **prefs)

        Sign a key or a user id within a key.

        :param subject: The user id or key to be certified.
        :type subject: :py:obj:`PGPKey`, :py:obj:`PGPUID`
        :param level: :py:obj:`~constants.SignatureType.Generic_Cert`, :py:obj:`~constants.SignatureType.Persona_Cert`,
                      :py:obj:`~constants.SignatureType.Casual_Cert`, or :py:obj:`~constants.SignatureType.Positive_Cert`.
                      Only used if subject is a :py:obj:`PGPUID`; otherwise, it is ignored.
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
        :returns: :py:obj:`PGPSignature`

        In addition to the optional keyword arguments accepted by :py:meth:`PGPKey.sign`, the following optional
        keyword arguments can be used with :py:meth:`PGPKey.certify`.

        These optional keywords only make sense, and thus only have an effect, when self-signing a key or User ID:

        :keyword usage: A ``set`` of key usage flags, as :py:obj:`~constants.KeyFlags`.
                        This keyword is ignored for non-self-certifications.
        :type usage: ``set``
        :keyword ciphers: A list of preferred symmetric ciphers, as :py:obj:`~constants.SymmetricKeyAlgorithm`.
                          This keyword is ignored for non-self-certifications.
        :type ciphers: ``list``
        :keyword hashes: A list of preferred hash algorithms, as :py:obj:`~constants.HashAlgorithm`.
                         This keyword is ignored for non-self-certifications.
        :type hashes: ``list``
        :keyword compression: A list of preferred compression algorithms, as :py:obj:`~constants.CompressionAlgorithm`.
                              This keyword is ignored for non-self-certifications.
        :type compression: ``list``
        :keyword key_expiration: Specify a key expiration date for when this key should expire, or a
                              :py:obj:`~datetime.timedelta` of how long after the key was created it should expire.
                              This keyword is ignored for non-self-certifications.
        :type key_expiration: :py:obj:`datetime.datetime`, :py:obj:`datetime.timedelta`
        :keyword attested_certifications: A list of third-party certifications, as :py:obj:`PGPSignature`, that
                                          the certificate holder wants to attest to for redistribution with the certificate.
                                          Alternatively, any element in the list can be a ``bytes``  or ``bytearray`` object
                                          of the appropriate length (the length of this certification's digest).
                                          This keyword is only used for signatures of type Attestation.
        :type attested_certifications: ``list``
        :keyword keyserver: Specify the URI of the preferred key server of the user.
                            This keyword is ignored for non-self-certifications.
        :type keyserver: ``str``, ``unicode``, ``bytes``
        :keyword keyserver_flags: A set of Key Server Preferences, as :py:obj:`~constants.KeyServerPreferences`.
        :type keyserver_flags: ``set``
        :keyword primary: Whether or not to consider the certified User ID as the primary one.
                          This keyword is ignored for non-self-certifications, and any certifications directly on keys.
        :type primary: ``bool``

        These optional keywords only make sense, and thus only have an effect, when signing another key or User ID:

        :keyword trust: Specify the level and amount of trust to assert when certifying a public key. Should be a tuple
                        of two ``int`` s, specifying the trust level and trust amount. See
                        `RFC 4880 Section 5.2.3.13. Trust Signature <https://tools.ietf.org/html/rfc4880#section-5.2.3.13>`_
                        for more on what these values mean.
        :type trust: ``tuple`` of two ``int`` s
        :keyword regex: Specify a regular expression to constrain the specified trust signature in the resulting signature.
                        Symbolically signifies that the specified trust signature only applies to User IDs which match
                        this regular expression.
                        This is meaningless without also specifying trust level and amount.
        :type regex: ``str``
        :keyword exportable: Whether this certification is exportable or not.
        :type exportable: ``bool``
        """
        pass

    @KeyAction(KeyFlags.Certify, is_unlocked=True, is_public=False)
    def revoke(self, target, **prefs):
        """
        Revoke a key, a subkey, or all current certification signatures of a User ID that were generated by this key so far.

        :param target: The key to revoke
        :type target: :py:obj:`PGPKey`, :py:obj:`PGPUID`
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
        :returns: :py:obj:`PGPSignature`

        In addition to the optional keyword arguments accepted by :py:meth:`PGPKey.sign`, the following optional
        keyword arguments can be used with :py:meth:`PGPKey.revoke`.

        :keyword reason: Defaults to :py:obj:`constants.RevocationReason.NotSpecified`
        :type reason: One of :py:obj:`constants.RevocationReason`.
        :keyword comment: Defaults to an empty string.
        :type comment: ``str``
        """
        pass

    @KeyAction(is_unlocked=True, is_public=False)
    def revoker(self, revoker, **prefs):
        """
        Generate a signature that specifies another key as being valid for revoking this key.

        :param revoker: The :py:obj:`PGPKey` to specify as a valid revocation key.
        :type revoker: :py:obj:`PGPKey`
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
        :returns: :py:obj:`PGPSignature`

        In addition to the optional keyword arguments accepted by :py:meth:`PGPKey.sign`, the following optional
        keyword arguments can be used with :py:meth:`PGPKey.revoker`.

        :keyword sensitive: If ``True``, this sets the sensitive flag on the RevocationKey subpacket. Currently,
                            this has no other effect.
        :type sensitive: ``bool``
        """
        pass

    @KeyAction(is_unlocked=True, is_public=False)
    def bind(self, key, **prefs):
        """
        Bind a subkey to this key.

        In addition to the optional keyword arguments accepted for self-signatures by :py:meth:`PGPkey.certify`,
        the following optional keyword arguments can be used with :py:meth:`PGPKey.bind`.

        :keyword crosssign: If ``False``, do not attempt a cross-signature (defaults to ``True``). Subkeys
                            which are not capable of signing will not produce a cross-signature in any case.
                            Setting ``crosssign`` to ``False`` is likely to produce subkeys that will be rejected
                            by some other OpenPGP implementations.
        :type crosssign: ``bool``
        """
        pass

    def is_considered_insecure(self, self_verifying=False):
        pass

    def self_verify(self):
        pass

    def _do_self_signatures_verification(self):
        pass

    @property
    def self_verified(self):
        pass

    def check_primitives(self):
        pass

    def check_management(self, self_verifying=False):
        pass

    def check_soundness(self, self_verifying=False):
        pass

    def verify(self, subject, signature=None):
        """
        Verify a subject with a signature using this key.

        :param subject: The subject to verify
        :type subject: ``str``, ``unicode``, ``None``, :py:obj:`PGPMessage`, :py:obj:`PGPKey`, :py:obj:`PGPUID`
        :param signature: If the signature is detached, it should be specified here.
        :type signature: :py:obj:`PGPSignature`
        :returns: :py:obj:`~pgpy.types.SignatureVerification`
        """
        pass

    @KeyAction(KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage, is_public=True)
    def encrypt(self, message, sessionkey=None, **prefs):
        """encrypt(message[, sessionkey=None], **prefs)

        Encrypt a PGPMessage using this key.

        :param message: The message to encrypt.
        :type message: :py:obj:`PGPMessage`
        :param sessionkey: Provide a session key to use when encrypting something. Default is ``None``.
                                    If ``None``, a session key of the appropriate length will be generated randomly.

                                    .. warning::

                                        Care should be taken when making use of this option! Session keys *absolutely need*
                                        to be unpredictable! Use the ``gen_key()`` method on the desired
                                        :py:obj:`~constants.SymmetricKeyAlgorithm` to generate the session key!
        :type sessionkey: ``bytes``, ``str``

        :raises: :py:exc:`~errors.PGPEncryptionError` if encryption failed for any reason.
        :returns: A new :py:obj:`PGPMessage` with the encrypted contents of ``message``

        The following optional keyword arguments can be used with :py:meth:`PGPKey.encrypt`:

        :keyword cipher: Specifies the symmetric block cipher to use when encrypting the message.
        :type cipher: :py:obj:`~constants.SymmetricKeyAlgorithm`
        :keyword user: Specifies the User ID to use as the recipient for this encryption operation, for the purposes of
                       preference defaults and selection validation.
        :type user: ``str``, ``unicode``
        """
        pass

    @KeyAction(is_unlocked=True, is_public=False)
    def decrypt(self, message):
        """
        Decrypt a PGPMessage using this key.

        :param message: An encrypted :py:obj:`PGPMessage`
        :raises: :py:exc:`~errors.PGPError` if the key is not private, or protected but not unlocked.
        :raises: :py:exc:`~errors.PGPDecryptionError` if decryption fails for any other reason.
        :returns: A new :py:obj:`PGPMessage` with the decrypted contents of ``message``.
        """
        pass

    def parse(self, data):
        unarmored = self.ascii_unarmor(data)
        data = unarmored['body']

        if unarmored['magic'] is not None and 'KEY' not in unarmored['magic']:
            raise ValueError('Expected: KEY. Got: {}'.format(str(unarmored['magic'])))

        if unarmored['headers'] is not None:
            self.ascii_headers = unarmored['headers']

        # parse packets
        # keys will hold other keys parsed here
        keys = collections.OrderedDict()
        # orphaned will hold all non-opaque orphaned packets
        orphaned = []
        # last holds the last non-signature thing processed

        ##TODO: see issue #141 and fix this better
        def _getpkt(d):
            pass
        # some packets are filtered out
        getpkt = filter(lambda p: p.header.tag != PacketTag.Trust, iter(functools.partial(_getpkt, data), None))

        def pktgrouper():
            class PktGrouper(object):
                def __init__(self):
                    self.last = None

                def __call__(self, pkt):
                    if pkt.header.tag != PacketTag.Signature:
                        self.last = '{:02X}_{:s}'.format(id(pkt), pkt.__class__.__name__)
                    return self.last
            return PktGrouper()

        while True:
            for group in iter(group for _, group in itertools.groupby(getpkt, key=pktgrouper()) if not _.endswith('Opaque')):
                pkt = next(group)

                # deal with pkt first
                if isinstance(pkt, Key):
                    pgpobj = (self if self._key is None else PGPKey()) | pkt

                elif isinstance(pkt, (UserID, UserAttribute)):
                    pgpobj = PGPUID() | pkt

                else:  # pragma: no cover
                    break

                # add signatures to whatever we got
                [ operator.ior(pgpobj, PGPSignature() | sig) for sig in group if not isinstance(sig, Opaque) ]

                # and file away pgpobj
                if isinstance(pgpobj, PGPKey):
                    if pgpobj.is_primary:
                        keys[(pgpobj.fingerprint.keyid, pgpobj.is_public)] = pgpobj

                    else:
                        keys[next(reversed(keys))] |= pgpobj

                elif isinstance(pgpobj, PGPUID):
                    # parent is likely the most recently parsed primary key
                    keys[next(reversed(keys))] |= pgpobj

                else:  # pragma: no cover
                    break
            else:
                # finished normally
                break

            # this will only be reached called if the inner loop hit a break
            warnings.warn("Warning: Orphaned packet detected! {:s}".format(repr(pkt)), stacklevel=2)  # pragma: no cover
            orphaned.append(pkt)  # pragma: no cover
            for pkt in group:  # pragma: no cover
                orphaned.append(pkt)

        # remove the reference to self from keys
        [ keys.pop((getattr(self, 'fingerprint.keyid', '~'), None), t) for t in (True, False) ]
        # return {'keys': keys, 'orphaned': orphaned}
        return keys


class PGPKeyring(collections_abc.Container, collections_abc.Iterable, collections_abc.Sized):
    def __init__(self, *args):
        """
        PGPKeyring objects represent in-memory keyrings that can contain any combination of supported private and public
        keys. It can not currently be conveniently exported to a format that can be understood by GnuPG.
        """
        super(PGPKeyring, self).__init__()
        self._keys = {}
        self._pubkeys = collections.deque()
        self._privkeys = collections.deque()
        self._aliases = collections.deque([{}])
        self.load(*args)

    def __contains__(self, alias):
        aliases = set().union(*self._aliases)

        if isinstance(alias, str):
            return alias in aliases or alias.replace(' ', '') in aliases

        return alias in aliases  # pragma: no cover

    def __len__(self):
        return len(self._keys)

    def __iter__(self):  # pragma: no cover
        for pgpkey in itertools.chain(self._pubkeys, self._privkeys):
            yield pgpkey

    def _get_key(self, alias):
        for m in self._aliases:
            if alias in m:
                return self._keys[m[alias]]

            if alias.replace(' ', '') in m:
                return self._keys[m[alias.replace(' ', '')]]

        raise KeyError(alias)

    def _get_keys(self, alias):
        pass

    def _sort_alias(self, alias):
        # remove alias from all levels of _aliases, and sort by created time and key half
        # so the order of _aliases from left to right:
        #  - newer keys come before older ones
        #  - private keys come before public ones
        #
        # this list is sorted in the opposite direction from that, because they will be placed into self._aliases
        # from right to left.
        pass

    def _add_alias(self, alias, pkid):
        # brand new alias never seen before!
        pass

    def _add_key(self, pgpkey):
        pass

    def load(self, *args):
        r"""
        Load all keys provided into this keyring object.

        :param \*args: Each arg in ``args`` can be any of the formats supported by :py:meth:`PGPKey.from_file` and
                      :py:meth:`PGPKey.from_blob` or a :py:class:`PGPKey` instance, or a ``list`` or ``tuple`` of these.
        :type \*args: ``list``, ``tuple``, ``str``, ``unicode``, ``bytes``, ``bytearray``
        :returns: a ``set`` containing the unique fingerprints of all of the keys that were loaded during this operation.
        """
        pass

    @contextlib.contextmanager
    def key(self, identifier):
        """
        A context-manager method. Yields the first :py:obj:`PGPKey` object that matches the provided identifier.

        :param identifier: The identifier to use to select a loaded key.
        :type identifier: :py:exc:`PGPMessage`, :py:exc:`PGPSignature`, ``str``
        :raises: :py:exc:`KeyError` if there is no loaded key that satisfies the identifier.
        """
        if isinstance(identifier, PGPMessage):
            for issuer in identifier.issuers:
                if issuer in self:
                    identifier = issuer
                    break

        if isinstance(identifier, PGPSignature):
            identifier = identifier.signer

        yield self._get_key(identifier)

    def fingerprints(self, keyhalf='any', keytype='any'):
        """
        List loaded fingerprints with some optional filtering.

        :param keyhalf: Can be 'any', 'public', or 'private'. If 'public', or 'private', the fingerprints of keys of the
                            the other type will not be included in the results.
        :type keyhalf: ``str``
        :param keytype: Can be 'any', 'primary', or 'sub'. If 'primary' or 'sub', the fingerprints of keys of the
                            the other type will not be included in the results.
        :type keytype: ``str``
        :returns: a ``set`` of fingerprints of keys matching the filters specified.
        """
        pass

    def unload(self, key):
        """
        Unload a loaded key and its subkeys.

        :param key: The key to unload.
        :type key: :py:obj:`PGPKey`

        The easiest way to do this is to select a key using :py:meth:`PGPKeyring.key` first::

            with keyring.key("DSA von TestKey") as key:
                keyring.unload(key)
        """
        pass
