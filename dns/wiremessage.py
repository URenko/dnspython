# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import binascii
import io
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

import dns.exception
import dns.flags
import dns.name
import dns.opcode
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.wire


@dataclass
class Question:
    """A Question in a dns.wiremessage.Message"""

    name: dns.name.Name
    rdclass: dns.rdataclass.RdataClass
    rdtype: dns.rdatatype.RdataType
    start: int
    end: int

    def to_text(self):
        name = self.name.to_text()
        rdclass = dns.rdataclass.to_text(self.rdclass)
        rdtype = dns.rdatatype.to_text(self.rdtype)
        return f"{name} {rdclass} {rdtype}"


@dataclass
class Error:
    offset: int
    exception: Exception


@dataclass
class RR:
    """An RR in a dns.wiremessage.Message"""

    name: dns.name.Name
    rdclass: dns.rdataclass.RdataClass
    rdtype: dns.rdatatype.RdataType
    ttl: int
    rdata: Optional[dns.rdata.Rdata]
    start: int
    end: int
    rdata_start: int
    error: Optional[Error]

    def rdlen(self):
        return self.end - self.rdata_start

    def to_text(self):
        name = self.name.to_text()
        rdclass = dns.rdataclass.to_text(self.rdclass)
        rdtype = dns.rdatatype.to_text(self.rdtype)
        if self.rdata is not None:
            rdata = " " + self.rdata.to_text()
        else:
            rdata = ""
        if self.error is not None:
            error = f" ; error:{self.error.offset:04x}: {self.error.exception}"
        else:
            error = ""
        return f"{name} {self.ttl} {rdclass} {rdtype}{rdata}{error}"


class Message:
    """A message class that preserves wire format."""

    def __init__(self, wire: bytes):
        self.wire: bytes = wire
        self.id: int = 0
        self.flags: int = 0
        self.qcount: int = 0
        self.ancount: int = 0
        self.aucount: int = 0
        self.adcount: int = 0
        self.question: Tuple[Question, ...] = ()
        self.answer: Tuple[RR, ...] = ()
        self.authority: Tuple[RR, ...] = ()
        self.additional: Tuple[RR, ...] = ()
        self.error: Optional[Error] = None
        self.trailing_offset: Optional[int] = None
        parser = dns.wire.Parser(wire)
        try:
            (
                self.id,
                self.flags,
                self.qcount,
                self.ancount,
                self.aucount,
                self.adcount,
            ) = parser.get_struct("!HHHHHH")
        except Exception as e:
            self.error = Error(parser.current, e)
        self.question = self._get_questions(parser, self.qcount)
        self.answer = self._get_rrs(parser, self.ancount)
        self.authority = self._get_rrs(parser, self.aucount)
        self.additional = self._get_rrs(parser, self.adcount)
        if self.error is None and parser.remaining() != 0:
            self.trailing_offset = parser.current

    def _get_questions(
        self, parser: dns.wire.Parser, count: int
    ) -> Tuple[Question, ...]:
        if self.error is not None:
            return ()
        records: List[Question] = []
        for _ in range(count):
            start = parser.current
            try:
                name = parser.get_name()
                (rdtype, rdclass) = parser.get_struct("!HH")
                end = parser.current
                records.append(Question(name, rdclass, rdtype, start, end))
            except Exception as e:
                parser.seek(start)
                self.error = Error(parser.current, e)
                break
        return tuple(records)

    def _get_rrs(self, parser: dns.wire.Parser, count: int) -> Tuple[RR, ...]:
        if self.error is not None:
            return ()
        records = []
        for _ in range(count):
            start = parser.current
            try:
                name = parser.get_name()
                (rdtype, rdclass, ttl, rdlen) = parser.get_struct("!HHIH")
                rdata_start = parser.current
                error = None
                if rdlen > 0:
                    with parser.restrict_to(rdlen):
                        try:
                            rdata = dns.rdata.from_wire_parser(
                                rdclass, rdtype, parser, None
                            )
                        except Exception as e:
                            rdata = None
                            error = Error(parser.current, e)
                            parser.seek(rdata_start + rdlen)
                else:
                    rdata = None
                end = parser.current
                records.append(
                    RR(
                        name,
                        rdclass,
                        rdtype,
                        ttl,
                        rdata,
                        start,
                        end,
                        rdata_start,
                        error,
                    )
                )
            except Exception as e:
                parser.seek(start)
                self.error = Error(parser.current, e)
                break
        return tuple(records)

    def opcode(self) -> dns.opcode.Opcode:
        return dns.opcode.from_flags(self.flags)

    def ednsflags(self) -> int:
        for rr in self.additional:
            if rr.rdtype == dns.rdatatype.OPT and rr.name == dns.name.root:
                return rr.ttl
        return 0

    def rcode(self) -> dns.rcode.Rcode:
        return dns.rcode.from_flags(self.flags, self.ednsflags())

    def slice(self, start: int, end: int) -> bytes:
        return self.wire[start:end]

    def hex(self, start: int, end: int) -> bytes:
        return binascii.hexlify(self.slice(start, end))

    def annotate_slice(
        self,
        output: io.StringIO,
        start: int,
        end: int,
        annotation: str,
        max_bytes: int = 16,
    ) -> None:
        pad_before = start % max_bytes
        where = start
        while where < end:
            output.write(f"{where:04x}: ")
            amount = min(end - where, max_bytes - pad_before)
            pad_after = max_bytes - amount - pad_before
            hex = self.hex(where, where + amount).decode()
            if pad_before > 0:
                output.write(pad_before * "  ")
                pad_before = 0
            output.write(hex)
            if where == start and len(annotation) > 0:
                if pad_after > 0:
                    output.write(pad_after * "  ")
                output.write(" ; ")
                output.write(annotation)
            output.write("\n")
            where += amount

    def question_section_to_text(self, output: io.StringIO) -> None:
        output.write("; QUESTION\n")
        for question in self.question:
            self.annotate_slice(
                output, question.start, question.end, question.to_text()
            )

    def rr_section_to_text(
        self, output: io.StringIO, section: Iterable[RR], section_name: str
    ) -> None:
        output.write(f"; {section_name}\n")
        for rr in section:
            self.annotate_slice(output, rr.start, rr.end, rr.to_text())

    def to_text(self):
        output = io.StringIO()
        output.write("; HEADER\n")
        self.annotate_slice(output, 0, 2, f"id = {self.id}")
        flags = (
            dns.opcode.to_text(self.opcode())
            + " "
            + dns.flags.to_text(self.flags)
            + " "
            + dns.rcode.to_text(self.rcode())
        )
        self.annotate_slice(output, 2, 4, f"flags = {flags}")
        self.annotate_slice(output, 4, 6, f"qcount = {self.qcount}")
        self.annotate_slice(output, 6, 8, f"ancount = {self.ancount}")
        self.annotate_slice(output, 8, 10, f"aucount = {self.aucount}")
        self.annotate_slice(output, 10, 12, f"adcount = {self.adcount}")
        self.question_section_to_text(output)
        self.rr_section_to_text(output, self.answer, "ANSWER")
        self.rr_section_to_text(output, self.authority, "AUTHORITY")
        self.rr_section_to_text(output, self.additional, "ADDITIONAL")
        if self.error is not None:
            output.write("; ERROR\n")
            self.annotate_slice(
                output,
                self.error.offset,
                len(self.wire),
                f"error:{self.error.offset:04x}: {self.error.exception}",
            )
        elif self.trailing_offset is not None:
            output.write("; TRAILING\n")
            self.annotate_slice(output, self.trailing_offset, len(self.wire), "")
        total = len(self.wire)
        output.write(f"; total length = {total}")
        return output.getvalue()
