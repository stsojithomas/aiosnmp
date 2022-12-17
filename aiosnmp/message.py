__all__ = (
    "PDU",
    "SnmpVersion",
    "SnmpVarbind",
    "SnmpMessage",
    "GetRequest",
    "GetNextRequest",
    "GetBulkRequest",
    "SetRequest",
    "SnmpResponse",
    "SnmpV2TrapMessage",
)

import binascii
import enum
import ipaddress
import random
from typing import List, Optional, Union

from .asn1 import Class, Number
from .asn1_rust import Decoder, Encoder
from .security import UserSecurityModel, MsgGlobalData


class SnmpVersion(enum.IntEnum):
    v1 = 0x00
    v2c = 0x01
    v3 = 0x03


class PDUType(enum.IntEnum):
    GetRequest = 0x00
    GetNextRequest = 0x01
    GetResponse = 0x02
    SetRequest = 0x03
    SNMPv1Trap = 0x04
    GetBulkRequest = 0x05
    InformRequest = 0x06
    SNMPv2Trap = 0x07
    Report = 0x08


class SnmpVarbind:
    __slots__ = ("_oid", "_value", "_number")

    def __init__(
            self,
            oid: str,
            value: Union[None, str, int, bytes, ipaddress.IPv4Address] = None,
            number: Optional[Number] = None,
    ) -> None:
        self._oid: str = oid.lstrip(".")
        self._value: Union[None, str, int, bytes, ipaddress.IPv4Address] = value
        self._number: Optional[Number] = number

    @property
    def oid(self) -> str:
        """This property stores oid of the message"""

        return f".{self._oid}"

    @property
    def value(self) -> Union[None, str, int, bytes, ipaddress.IPv4Address]:
        """This property stores value of the message"""

        return self._value

    @property
    def number(self) -> Optional[Number]:
        """This property stores number of the message"""

        return self._number

    def encode(self, encoder: Encoder) -> None:
        encoder.enter(Number.Sequence)
        encoder.write(self._oid, Number.ObjectIdentifier)
        encoder.write(self.value, self.number)
        encoder.exit()


class PDU:
    __slots__ = ("request_id", "error_status", "error_index", "varbinds")

    _PDUType: PDUType

    def __init__(self, varbinds: List[SnmpVarbind]) -> None:
        self.request_id = random.randrange(1, 2_147_483_647)
        self.error_status: int = 0
        self.error_index: int = 0
        self.varbinds: List[SnmpVarbind] = varbinds

    def encode(self, encoder: Encoder) -> None:
        encoder.enter(self._PDUType, Class.Context)
        encoder.write(self.request_id, Number.Integer)
        encoder.write(self.error_status, Number.Integer)
        encoder.write(self.error_index, Number.Integer)

        encoder.enter(Number.Sequence)
        for varbind in self.varbinds:
            varbind.encode(encoder)
        encoder.exit()

        encoder.exit()


class BulkPDU:
    __slots__ = ("request_id", "non_repeaters", "max_repetitions", "varbinds")

    _PDUType: PDUType

    def __init__(self, varbinds: List[SnmpVarbind], non_repeaters: int, max_repetitions: int) -> None:
        self.request_id = random.randrange(1, 2_147_483_647)
        self.non_repeaters: int = non_repeaters
        self.max_repetitions: int = max_repetitions
        self.varbinds: List[SnmpVarbind] = varbinds

    def encode(self, encoder: Encoder) -> None:
        encoder.enter(self._PDUType, Class.Context)
        encoder.write(self.request_id, Number.Integer)
        encoder.write(self.non_repeaters, Number.Integer)
        encoder.write(self.max_repetitions, Number.Integer)

        encoder.enter(Number.Sequence)
        for varbind in self.varbinds:
            varbind.encode(encoder)
        encoder.exit()

        encoder.exit()


class GetRequest(PDU):
    _PDUType: PDUType = PDUType.GetRequest


class GetNextRequest(PDU):
    _PDUType: PDUType = PDUType.GetNextRequest


class GetResponse(PDU):
    _PDUType: PDUType = PDUType.GetResponse


class SetRequest(PDU):
    _PDUType: PDUType = PDUType.SetRequest


class GetBulkRequest(BulkPDU):
    _PDUType: PDUType = PDUType.GetBulkRequest


class SnmpV2Trap(PDU):
    _PDUType: PDUType = PDUType.SNMPv2Trap


PDUs = Union[PDU, BulkPDU]


class SnmpMessage:
    __slots__ = ("version", "community", "usm_security_model", "data")

    def __init__(self, version: SnmpVersion,
                 community: str,
                 usm_security_model: UserSecurityModel,
                 data: PDUs) -> None:
        self.version: SnmpVersion = version
        self.community: str = community
        self.data: PDUs = data
        self.usm_security_model: UserSecurityModel = usm_security_model

    def encode(self) -> bytes:
        if self.version == SnmpVersion.v3:
            return self._encode_v3()
        encoder = Encoder()
        encoder.enter(Number.Sequence)
        encoder.write(self.version, Number.Integer)
        encoder.write(self.community, Number.OctetString)
        self.data.encode(encoder)
        encoder.exit()
        return encoder.output()

    def _encode_v3(self):
        encoder = Encoder()
        encoder.enter(Number.Sequence)
        encoder.write(self.version, Number.Integer)
        self.usm_security_model.encode(encoder)
        scoped_pdu_encoder = Encoder()
        scoped_pdu_encoder.enter(Number.Sequence)
        scoped_pdu_encoder.write(binascii.unhexlify(self.usm_security_model.context_engine_id), Number.OctetString)
        scoped_pdu_encoder.write(self.usm_security_model.context_engine_name, Number.OctetString)
        self.data.encode(scoped_pdu_encoder)
        scoped_pdu_encoder.exit()
        encoder.append(scoped_pdu_encoder.output())
        encoder.exit()
        return encoder.output()


class SnmpResponse(SnmpMessage):
    @classmethod
    def decode(cls, data: bytes) -> "SnmpResponse":
        decoder = Decoder(data)
        decoder.enter()  # 1
        tag, value = decoder.read()
        version = SnmpVersion(value)
        print(f"version: {version}")
        if version == SnmpVersion.v3:
            snmp_response: SnmpResponse = SnmpResponse.decode_v3(version, decoder)
            decoder.exit()  # 1
            return snmp_response

        tag, value = decoder.read()
        community = value.decode()

        decoder.enter()  # 2
        tag, value = decoder.read()
        request_id = value

        tag, value = decoder.read()
        error_status = value

        tag, value = decoder.read()
        error_index = value

        decoder.enter()  # 3
        varbinds: List[SnmpVarbind] = []
        while not decoder.eof():
            decoder.enter()  # 4
            _, value = decoder.read()
            oid = value
            _, value = decoder.read()
            varbinds.append(SnmpVarbind(oid, value))
            decoder.exit()  # 4

        decoder.exit()  # 3

        decoder.exit()  # 2

        decoder.exit()  # 1

        response = GetResponse(varbinds)
        response.request_id = request_id
        response.error_status = error_status
        response.error_index = error_index
        return cls(version=version,
                   community=community,
                   usm_security_model=None,
                   data=response)

    @classmethod
    def decode_v3(cls, version: SnmpVersion, decoder: Decoder) -> "SnmpResponse":

        msg_global_data: MsgGlobalData = MsgGlobalData.decode(decoder)
        usm: UserSecurityModel = UserSecurityModel.decode(decoder)
        usm.msg_global_data = msg_global_data

        decoder.enter()  # msgData
        tag, value = decoder.read()
        context_engine_id = str(binascii.hexlify(value), 'UTF-8')
        usm.context_engine_id = context_engine_id
        tag, value = decoder.read()
        usm.context_engine_name = value

        decoder.enter()  # data
        tag, value = decoder.read()
        request_id = value

        tag, value = decoder.read()
        error_status = value

        tag, value = decoder.read()
        error_index = value

        decoder.enter()  # variable-bindings
        varbinds: List[SnmpVarbind] = []
        while not decoder.eof():
            decoder.enter()  # variable-binding
            _, value = decoder.read()
            oid = value
            _, value = decoder.read()
            varbinds.append(SnmpVarbind(oid, value))
            decoder.exit()  # variable-binding

        decoder.exit()  # variable-bindings

        decoder.exit()  # data

        decoder.exit()  # msgData

        response = GetResponse(varbinds)
        response.request_id = request_id
        response.error_status = error_status
        response.error_index = error_index
        return cls(version=version,
                   community='',
                   usm_security_model=usm,
                   data=response)


class SnmpV2TrapMessage:
    __slots__ = ("_version", "_community", "_data")

    def __init__(self, version: SnmpVersion, community: str, data: PDU) -> None:
        self._version: SnmpVersion = version
        self._community: str = community
        self._data: PDU = data

    @property
    def version(self) -> SnmpVersion:
        """Returns version of the message"""
        return self._version

    @property
    def community(self) -> str:
        """Returns community of the message"""
        return self._community

    @property
    def data(self) -> PDU:
        """Returns :class:`protocol data unit <PDU>` of the message"""
        return self._data

    @classmethod
    def decode(cls, data: bytes) -> Optional["SnmpV2TrapMessage"]:
        decoder = Decoder(data)
        decoder.enter()  # 1
        tag, value = decoder.read()
        version = SnmpVersion(value)
        if version != SnmpVersion.v2c:
            return None

        tag, value = decoder.read()
        community = value.decode()

        tag = decoder.peek()
        if tag.cls != Class.Context or tag.number != PDUType.SNMPv2Trap:
            return None

        decoder.enter()  # 2
        tag, value = decoder.read()
        request_id = value

        tag, value = decoder.read()
        error_status = value

        tag, value = decoder.read()
        error_index = value

        decoder.enter()  # 3
        varbinds: List[SnmpVarbind] = []
        while not decoder.eof():
            decoder.enter()  # 4
            _, value = decoder.read()
            oid = value
            _, value = decoder.read()
            varbinds.append(SnmpVarbind(oid, value))
            decoder.exit()  # 4

        decoder.exit()  # 3

        decoder.exit()  # 2

        decoder.exit()  # 1

        response = SnmpV2Trap(varbinds)
        response.request_id = request_id
        response.error_status = error_status
        response.error_index = error_index
        return cls(version, community, response)
