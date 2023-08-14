# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license
import binascii

from dns.wiremessage import Message

wire1 = binascii.unhexlify(
    b"04d28180000100040000000109646e73707974686f6e036f72670000020001"
    + b"c00c0002000100000e100014076e732d3132353309617773646e732d3238c0"
    + b"16c00c0002000100000e100019076e732d3230323009617773646e732d3630"
    + b"02636f02756b00c00c0002000100000e100016066e732d3531380961777364"
    + b"6e732d3030036e657400c00c0002000100000e100016066e732d3334330961"
    + b"7773646e732d343203636f6d000000292000000000000000"
)


def _compare_one(wire, expected):
    m = Message(wire)
    text = m.to_text()
    assert text == expected


text1 = """; HEADER
0000: 04d2                             ; id = 1234
0002:     8180                         ; flags = QUERY QR RD RA NOERROR
0004:         0001                     ; qcount = 1
0006:             0004                 ; ancount = 4
0008:                 0000             ; aucount = 0
000a:                     0001         ; adcount = 1
; QUESTION
000c:                         09646e73 ; dnspython.org. IN NS
0010: 707974686f6e036f72670000020001
; ANSWER
001f:                               c0 ; dnspython.org. 3600 IN NS ns-1253.awsdns-28.org.
0020: 0c0002000100000e100014076e732d31
0030: 32353309617773646e732d3238c016
003f:                               c0 ; dnspython.org. 3600 IN NS ns-2020.awsdns-60.co.uk.
0040: 0c0002000100000e100019076e732d32
0050: 30323009617773646e732d363002636f
0060: 02756b00
0064:         c00c0002000100000e100016 ; dnspython.org. 3600 IN NS ns-518.awsdns-00.net.
0070: 066e732d35313809617773646e732d30
0080: 30036e657400
0086:             c00c0002000100000e10 ; dnspython.org. 3600 IN NS ns-343.awsdns-42.com.
0090: 0016066e732d33343309617773646e73
00a0: 2d343203636f6d00
; AUTHORITY
; ADDITIONAL
00a8:                 0000292000000000 ; . 0 CLASS8192 OPT
00b0: 000000
; total length = 179"""


def test_basic():
    _compare_one(wire1, text1)


wire2 = wire1[:31] + 150 * b"\xff"

text2 = """; HEADER
0000: 04d2                             ; id = 1234
0002:     8180                         ; flags = QUERY QR RD RA NOERROR
0004:         0001                     ; qcount = 1
0006:             0004                 ; ancount = 4
0008:                 0000             ; aucount = 0
000a:                     0001         ; adcount = 1
; QUESTION
000c:                         09646e73 ; dnspython.org. IN NS
0010: 707974686f6e036f72670000020001
; ANSWER
; AUTHORITY
; ADDITIONAL
; ERROR
001f:                               ff ; error:001f: A DNS compression pointer points forward instead of backward.
0020: ffffffffffffffffffffffffffffffff
0030: ffffffffffffffffffffffffffffffff
0040: ffffffffffffffffffffffffffffffff
0050: ffffffffffffffffffffffffffffffff
0060: ffffffffffffffffffffffffffffffff
0070: ffffffffffffffffffffffffffffffff
0080: ffffffffffffffffffffffffffffffff
0090: ffffffffffffffffffffffffffffffff
00a0: ffffffffffffffffffffffffffffffff
00b0: ffffffffff
; total length = 181"""


def test_bad_owner_name():
    _compare_one(wire2, text2)


wire3 = wire1 + b"some trailing junk"

text3 = """; HEADER
0000: 04d2                             ; id = 1234
0002:     8180                         ; flags = QUERY QR RD RA NOERROR
0004:         0001                     ; qcount = 1
0006:             0004                 ; ancount = 4
0008:                 0000             ; aucount = 0
000a:                     0001         ; adcount = 1
; QUESTION
000c:                         09646e73 ; dnspython.org. IN NS
0010: 707974686f6e036f72670000020001
; ANSWER
001f:                               c0 ; dnspython.org. 3600 IN NS ns-1253.awsdns-28.org.
0020: 0c0002000100000e100014076e732d31
0030: 32353309617773646e732d3238c016
003f:                               c0 ; dnspython.org. 3600 IN NS ns-2020.awsdns-60.co.uk.
0040: 0c0002000100000e100019076e732d32
0050: 30323009617773646e732d363002636f
0060: 02756b00
0064:         c00c0002000100000e100016 ; dnspython.org. 3600 IN NS ns-518.awsdns-00.net.
0070: 066e732d35313809617773646e732d30
0080: 30036e657400
0086:             c00c0002000100000e10 ; dnspython.org. 3600 IN NS ns-343.awsdns-42.com.
0090: 0016066e732d33343309617773646e73
00a0: 2d343203636f6d00
; AUTHORITY
; ADDITIONAL
00a8:                 0000292000000000 ; . 0 CLASS8192 OPT
00b0: 000000
; TRAILING
00b3:       736f6d6520747261696c696e67
00c0: 206a756e6b
; total length = 197"""


def test_trailing_junk():
    _compare_one(wire3, text3)


wire4 = wire1[:41] + b"\xff\xff" + wire1[43:]

text4 = """; HEADER
0000: 04d2                             ; id = 1234
0002:     8180                         ; flags = QUERY QR RD RA NOERROR
0004:         0001                     ; qcount = 1
0006:             0004                 ; ancount = 4
0008:                 0000             ; aucount = 0
000a:                     0001         ; adcount = 1
; QUESTION
000c:                         09646e73 ; dnspython.org. IN NS
0010: 707974686f6e036f72670000020001
; ANSWER
; AUTHORITY
; ADDITIONAL
; ERROR
001f:                               c0 ; error:001f: DNS message is malformed.
0020: 0c0002000100000e10ffff076e732d31
0030: 32353309617773646e732d3238c016c0
0040: 0c0002000100000e100019076e732d32
0050: 30323009617773646e732d363002636f
0060: 02756b00c00c0002000100000e100016
0070: 066e732d35313809617773646e732d30
0080: 30036e657400c00c0002000100000e10
0090: 0016066e732d33343309617773646e73
00a0: 2d343203636f6d000000292000000000
00b0: 000000
; total length = 179"""


def test_bad_rdlen():
    _compare_one(wire4, text4)


wire5 = wire1[:43] + b"\xff\xff" + wire1[45:]

text5 = """; HEADER
0000: 04d2                             ; id = 1234
0002:     8180                         ; flags = QUERY QR RD RA NOERROR
0004:         0001                     ; qcount = 1
0006:             0004                 ; ancount = 4
0008:                 0000             ; aucount = 0
000a:                     0001         ; adcount = 1
; QUESTION
000c:                         09646e73 ; dnspython.org. IN NS
0010: 707974686f6e036f72670000020001
; ANSWER
001f:                               c0 ; dnspython.org. 3600 IN NS ; error:002d: A DNS compression pointer points forward instead of backward.
0020: 0c0002000100000e100014ffff732d31
0030: 32353309617773646e732d3238c016
003f:                               c0 ; dnspython.org. 3600 IN NS ns-2020.awsdns-60.co.uk.
0040: 0c0002000100000e100019076e732d32
0050: 30323009617773646e732d363002636f
0060: 02756b00
0064:         c00c0002000100000e100016 ; dnspython.org. 3600 IN NS ns-518.awsdns-00.net.
0070: 066e732d35313809617773646e732d30
0080: 30036e657400
0086:             c00c0002000100000e10 ; dnspython.org. 3600 IN NS ns-343.awsdns-42.com.
0090: 0016066e732d33343309617773646e73
00a0: 2d343203636f6d00
; AUTHORITY
; ADDITIONAL
00a8:                 0000292000000000 ; . 0 CLASS8192 OPT
00b0: 000000
; total length = 179"""


def test_bad_name_in_rdata():
    _compare_one(wire5, text5)
