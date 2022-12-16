from __future__ import annotations

import binascii
import enum
import random
import hashlib

from .asn1 import Number
from .asn1_rust import Encoder, Decoder


class AuthenticationProtocols(enum.IntEnum):
    NONE = 0x00
    MD5 = 0x01
    SHA1 = 0x02


class PrivacyProtocols(enum.IntEnum):
    NONE = 0x00
    DES = 0x01
    AES128 = 0x02
    AES192 = 0x03
    AES256 = 0x04
    TripleDES = 0x05


class SecurityLevels(enum.IntEnum):
    NoAuthNoPriv = 0x00
    AuthNoPriv = 0x01
    AuthPriv = 0x02


class MsgFlags(enum.IntEnum):
    NONE = 0X00
    FLAG_AUTH = 0x01
    FLAG_PRIV = 0x02
    FLAG_REPORTABLE = 0x04


class MsgGlobalData:
    __slots__ = ("message_id", "msg_max_size", "msg_security_model",
                 "_msg_flags",
                 "is_reportable", "is_authenticated", "is_encrypted")

    def __init__(self, *,
                 is_reportable: bool = True,
                 is_authenticated: bool = False,
                 is_encrypted: bool = False,
                 message_id: int = random.randrange(1, 2_147_483_647),
                 msg_max_size: int = 64 * 1024
                 ) -> None:
        self.is_reportable = is_reportable
        self.is_authenticated = is_authenticated
        self.is_encrypted = is_encrypted
        self.message_id = message_id
        self.msg_max_size = msg_max_size
        self.msg_security_model = 0x03
        self._msg_flags: MsgFlags = MsgFlags.NONE
        if is_reportable:
            self._msg_flags |= MsgFlags.FLAG_REPORTABLE
        if is_authenticated:
            self._msg_flags |= MsgFlags.FLAG_AUTH
        if is_encrypted:
            self._msg_flags |= MsgFlags.FLAG_PRIV

    def __str__(self):
        kvp = {}
        for attr in self.__slots__:
            kvp[f"{type(self)}.{attr}"] = getattr(self, attr)
        return str(kvp)

    def set_flag_value(self, msg_flags):
        self._msg_flags = msg_flags
        self.is_reportable = msg_flags & MsgFlags.FLAG_REPORTABLE
        self.is_authenticated = msg_flags & MsgFlags.FLAG_AUTH
        self.is_encrypted = msg_flags & MsgFlags.FLAG_PRIV

    def encode(self, encoder: Encoder) -> None:
        encoder.enter(Number.Sequence)
        encoder.write(self.message_id, Number.Integer)
        encoder.write(self.msg_max_size, Number.Integer)
        encoder.write(str(self._msg_flags), Number.OctetString)
        encoder.write(self.msg_security_model, Number.Integer)
        encoder.exit()

    @classmethod
    def decode(cls, decoder) -> "MsgGlobalData":
        decoder.enter()  # MsgGlobalData
        tag, value = decoder.read()
        message_id = value

        tag, value = decoder.read()
        msg_max_size = value

        tag, value = decoder.read()
        _msg_flags = int(binascii.hexlify(value).decode('UTF-8'))

        tag, value = decoder.read()
        msg_security_model = value
        decoder.exit()  # MsgGlobalData

        msg_global_data = cls(message_id=message_id, msg_max_size=msg_max_size)
        msg_global_data.set_flag_value(_msg_flags)
        return msg_global_data


class UserSecurityModel:
    __slots__ = ("security_engine_id", "context_engine_id", "context_engine_name",
                 "engine_boots", "engine_time", "security_level", "user_name",
                 "auth_protocol", "auth_key", "priv_protocol",
                 "priv_key", "msg_global_data")

    def __init__(self,
                 user_name: str = '',
                 auth_protocol=None,
                 auth_key='',
                 priv_protocol=None,
                 priv_key='',
                 msg_global_data: MsgGlobalData = MsgGlobalData()) -> None:
        self.user_name = user_name
        self.auth_protocol = auth_protocol
        self.auth_key = auth_key
        self.priv_protocol = priv_protocol
        self.priv_key = priv_key
        self.security_engine_id: str = ''
        self.context_engine_id: str = ''
        self.context_engine_name: str = ''
        self.engine_boots: int = 0
        self.engine_time: int = 0
        self.msg_global_data = msg_global_data
        if self.auth_key and self.priv_key:
            self.security_level = SecurityLevels.AuthPriv
        elif self.auth_key and self.priv_key is None:
            self.security_level = SecurityLevels.AuthNoPriv
        elif self.auth_key is '' and self.priv_key is '':
            self.security_level = SecurityLevels.NoAuthNoPriv
        else:
            # TODO
            raise Exception("Invalid security")

    def __str__(self):
        kvp = {}
        for attr in self.__slots__:
            kvp[f"{type(self)}.{attr}"] = getattr(self, attr, "")
        return str(kvp)

    def add_discovered_params(self, discovered_usm: UserSecurityModel) -> "UserSecurityModel":
        self.security_engine_id = discovered_usm.security_engine_id
        self.context_engine_id = discovered_usm.context_engine_id
        self.context_engine_name = discovered_usm.context_engine_name
        self.engine_boots = discovered_usm.engine_boots
        self.engine_time = discovered_usm.engine_time
        return self

    def set_discovery_mode(self) -> "UserSecurityModel":
        self.security_engine_id = ''
        self.context_engine_id = ''
        self.context_engine_name = ''
        self.engine_boots = 0
        self.engine_time = 0
        return self

    def encode(self, encoder: Encoder) -> None:
        self.msg_global_data.encode(encoder)
        security_encoder = Encoder()
        security_encoder.enter(Number.Sequence)
        security_encoder.write(self.security_engine_id, Number.OctetString)
        security_encoder.write(self.engine_boots, Number.Integer)
        security_encoder.write(self.engine_time, Number.Integer)
        security_encoder.write(self.user_name, Number.OctetString)
        encrypted_auth_key = hashlib.sha1(self.auth_key.encode('UTF-8')).hexdigest() if self.auth_key else self.auth_key
        security_encoder.write(encrypted_auth_key, Number.OctetString)
        encrypted_priv_key = hashlib.sha256(self.priv_key.encode('UTF-8')).hexdigest() if self.priv_key else self.priv_key
        security_encoder.write(encrypted_priv_key, Number.OctetString)
        security_encoder.exit()
        encoder.write(security_encoder.output(), Number.OctetString)

    @classmethod
    def decode(cls, decoder: Decoder) -> "UserSecurityModel":
        tag, value = decoder.read()  # UsmSecurityParameters
        security_decoder = Decoder(value)
        security_decoder.enter()  # UsmSecurityParameters
        tag, value = security_decoder.read()
        security_engine_id = binascii.hexlify(value).decode('UTF-8')

        tag, value = security_decoder.read()
        engine_boots = value

        tag, value = security_decoder.read()
        engine_time = value

        tag, value = security_decoder.read()
        user_name = value

        tag, value = security_decoder.read()
        auth_key = value.decode('UTF-8')

        tag, value = security_decoder.read()
        priv_key = value.decode('UTF-8')

        security_decoder.exit()  # UsmSecurityParameters
        usm = cls(user_name=user_name,
                  auth_key=auth_key,
                  priv_key=priv_key)
        usm.security_engine_id=security_engine_id
        usm.engine_boots=engine_boots
        usm.engine_time=engine_time
        return usm
