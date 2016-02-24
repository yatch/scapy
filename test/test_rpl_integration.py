import logging
import unittest
from scapy.all import *

class Dissection(unittest.TestCase):
    def setUp(self):
        self.log = logging.getLogger('test_logger')
        self.dissect = Dot15d4FCS
        LoWPAN_IPHC.set_context(0, 'aaaa::/64')

    def test_dissect_dis(self):
        str = b'\x41\xd8\x28\xcd\xab\xff\xff\x02\x00\x02\x00\x02\x00\x02\x00\x7a\x3b\x3a\x1a\x9b\x00\x65\x19\x00\x00\xe6\xa9'
        a = self.dissect(str)
        self.assertEqual(a[IPv6].src, 'fe80::202:2:2:2')
        self.assertEqual(a[IPv6].dst, 'ff02::1a')
        self.assertTrue(a[ICMPv6RPL_DIS] is not None)

    def test_dissect_ns(self):
        str = b'\x61\xdc\x6c\xcd\xab\x03\x00\x03\x00\x03\x00\x03\x00\x07\x00\x07\x00\x07\x00\x07\x00\x7b\xf7\x00\x3a\x87\x00\x4d\xc5\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\x01\x02\x00\x07\x00\x07\x00\x07\x00\x07\x00\x00\x00\x00\x00\x00\x21\x02\x00\x00\x00\x00\x02\x58\x00\x07\x00\x07\x00\x07\x00\x07\xce\x6a'
        a = self.dissect(str)
        self.assertEqual(a[IPv6].src, 'aaaa::207:7:7:7')
        self.assertEqual(a[IPv6].dst, 'aaaa::203:3:3:3')
        self.assertEqual(a[ICMPv6ND_NS].tgt, 'aaaa::203:3:3:3')
        self.assertEqual(a[ICMPv6NDOptSrcLLAddr].eui64, "00:07:00:07:00:07:00:07")
        self.assertEqual(a[ICMPv6NDOptARO].eui64, "00:07:00:07:00:07:00:07")

    def test_dissect_na(self):
        str = b'\x61\xdc\x13\xcd\xab\x07\x00\x07\x00\x07\x00\x07\x00\x03\x00\x03\x00\x03\x00\x03\x00\x7b\xf7\x00\x3a\x88\x00\x6d\xf2\xe0\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\x21\x02\x00\x00\x00\x00\x02\x58\x00\x07\x00\x07\x00\x07\x00\x07\x48\x15'
        a = self.dissect(str)
        self.assertEqual(a[IPv6].src, 'aaaa::203:3:3:3')
        self.assertEqual(a[IPv6].dst, 'aaaa::207:7:7:7')
        self.assertEqual(a[ICMPv6ND_NA].tgt, 'aaaa::203:3:3:3')
        self.assertEqual(a[ICMPv6NDOptARO].eui64, "00:07:00:07:00:07:00:07")

    def test_dissect_dio(self):
        str = b'\x41\xd8\x12\xcd\xab\xff\xff\x03\x00\x03\x00\x03\x00\x03\x00\x7a\x3b\x3a\x1a\x9b\x01\x80\xe2\x1e\xf0\x01\x00\x08\xf0\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\x04\x0e\x00\x08\x0c\x0a\x07\x00\x01\x00\x00\x01\x00\xff\xff\xff\x08\x1e\x40\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\x0b\x1a'
        a = self.dissect(str)
        self.assertEqual(a[IPv6].src, 'fe80::203:3:3:3')
        self.assertEqual(a[IPv6].dst, 'ff02::1a')
        self.assertEqual(a[ICMPv6RPL_DIO].dodagid, 'aaaa::203:3:3:3')
        self.assertEqual(a[ICMPv6RPLOptDODAGConfiguration].lifetimeunit, 65535)
        self.assertEqual(a[ICMPv6RPLOptPrefixInformation].R, 1)
        self.assertEqual(a[ICMPv6RPLOptPrefixInformation].prefixlen, 64)
        self.assertEqual(a[ICMPv6RPLOptPrefixInformation].prefix, 'aaaa::203:3:3:3')

    def test_dissect_dao(self):
        str = b'\x61\xdc\x6d\xcd\xab\x03\x00\x03\x00\x03\x00\x03\x00\x07\x00\x07\x00\x07\x00\x07\x00\x7a\xf7\x00\x3a\x9b\x02\xd8\x79\x1e\xc0\x00\xf1\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\x05\x12\x00\x80\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x07\x00\x07\x00\x07\x00\x07\x06\x14\x00\x00\x00\xff\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\xef\xd4'
        a = self.dissect(str)
        self.assertEqual(a[IPv6].src, 'aaaa::207:7:7:7')
        self.assertEqual(a[IPv6].dst, 'aaaa::203:3:3:3')
        self.assertEqual(a[ICMPv6RPL_DAO].dodagid, 'aaaa::203:3:3:3')
        self.assertEqual(a[ICMPv6RPLOptRPLTarget].prefix, 'aaaa::207:7:7:7/128')
        self.assertEqual(a[ICMPv6RPLOptTransitInformation].address, 'aaaa::203:3:3:3')

    def test_dissect_dao_ack(self):
        str = b'\x61\xdc\x14\xcd\xab\x07\x00\x07\x00\x07\x00\x07\x00\x03\x00\x03\x00\x03\x00\x03\x00\x7a\xf7\x00\x3a\x9b\x03\xfc\x3b\x1e\x00\xf1\x00\x62\x00'
        a = self.dissect(str)
        self.assertEqual(a[IPv6].src, 'aaaa::203:3:3:3')
        self.assertEqual(a[IPv6].dst, 'aaaa::207:7:7:7')
        self.assertEqual(a[ICMPv6RPL_DAO_ACK].daosequence, 241)
        self.assertEqual(a[ICMPv6RPL_DAO_ACK].status, 0)

    def test_dissect_dao_ack_with_srh(self):
        str = b'\x61\xdc\x1e\xcd\xab\x07\x00\x07\x00\x07\x00\x07\x00\x03\x00\x03\x00\x03\x00\x03\x00\x7a\xf7\x00\x2b\x3a\x03\x03\x03\x99\x30\x00\x00\x08\x00\x08\x00\x08\x00\x08\x04\x00\x04\x00\x04\x00\x04\x01\x00\x01\x00\x01\x00\x01\x00\x00\x00\x9b\x03\xfc\x53\x1e\x00\xf1\x00\xe8\x8d'
        a = self.dissect(str)
        self.assertEqual(a[IPv6].src, 'aaaa::203:3:3:3')
        self.assertEqual(a[IPv6].dst, 'aaaa::207:7:7:7')
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].segleft, 3)
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].CmprI, 9)
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].CmprE, 9)
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].pad, 3)
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].addresses, ['aaaa::208:8:8:8', 'aaaa::204:4:4:4'])
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].last, 'aaaa::201:1:1:1')
        self.assertEqual(a[ICMPv6RPL_DAO_ACK].daosequence, 241)
        self.assertEqual(a[ICMPv6RPL_DAO_ACK].status, 0)

    def test_dissect_udp(self):
        str = b'\x61\xdc\x33\xcd\xab\x05\x00\x05\x00\x05\x00\x05\x00\x02\x00\x02\x00\x02\x00\x02\x00\x7e\xf5\x00\x02\x01\x00\x01\x00\x01\x00\x01\xf0\x04\xd2\x04\xd2\xe5\x64\x4d\x65\x73\x73\x61\x67\x65\x20\x30\x00\xb6\xc7' 
        a = self.dissect(str)
        self.assertEqual(a[IPv6].src, 'aaaa::202:2:2:2')
        self.assertEqual(a[IPv6].dst, 'aaaa::201:1:1:1')
        self.assertEqual(a[UDP].sport, 1234)
        self.assertEqual(a[UDP].dport, 1234)

    def test_dissect_udp2(self):
        str = b'\x61\xdc\x2d\xcd\xab\x06\x00\x06\x00\x06\x00\x06\x00\x05\x00\x05\x00\x05\x00\x05\x00\x7c\xd5\x00\x3f\x02\x02\x00\x02\x00\x02\x00\x02\x02\x01\x00\x01\x00\x01\x00\x01\xf0\x04\xd2\x04\xd2\xe5\x64\x4d\x65\x73\x73\x61\x67\x65\x20\x30\x00\x85\xed'
        a = self.dissect(str)
        log.debug(a.show())
        self.assertEqual(a[IPv6].src, 'aaaa::202:2:2:2')
        self.assertEqual(a[IPv6].dst, 'aaaa::201:1:1:1')
        self.assertEqual(a[UDP].sport, 1234)
        self.assertEqual(a[UDP].dport, 1234)

    def test_dissect_udp_with_srh(self):
        str = b'\x61\xdc\xa9\xcd\xab\x08\x00\x08\x00\x08\x00\x08\x00\x07\x00\x07\x00\x07\x00\x07\x00\x78\xd7\x00\x2b\x3f\x02\x03\x00\x03\x00\x03\x00\x03\x29\x03\x03\x02\x99\x30\x00\x00\x07\x00\x07\x00\x07\x00\x07\x04\x00\x04\x00\x04\x00\x04\x01\x00\x01\x00\x01\x00\x01\x00\x00\x00\x60\x00\x00\x00\x00\x12\x11\x3c\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x02\x00\x02\x00\x02\x00\x02\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x01\x00\x01\x00\x01\x00\x01\x04\xd2\x04\xd2\x00\x12\xe5\x64\x4d\x65\x73\x73\x61\x67\x65\x20\x30\x00\x9a\x12'
        a = self.dissect(str)
        self.assertEqual(a[IPv6].src, 'aaaa::203:3:3:3')
        self.assertEqual(a[IPv6].dst, 'aaaa::208:8:8:8')
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].segleft, 2)
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].CmprI, 9)
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].CmprE, 9)
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].pad, 3)
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].addresses, ['aaaa::207:7:7:7', 'aaaa::204:4:4:4'])
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting].last, 'aaaa::201:1:1:1')
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting][IPv6].src, 'aaaa::202:2:2:2')
        self.assertEqual(a[IPv6ExtHdrRPLSourceRouting][IPv6].dst, 'aaaa::201:1:1:1')
        self.assertEqual(a[UDP].sport, 1234)
        self.assertEqual(a[UDP].dport, 1234)

    def test_dissect_udp_with_rplopt(self):
        str = b'\x61\xdc\x52\xcd\xab\x04\x00\x04\x00\x04\x00\x04\x00\x08\x00\x08\x00\x08\x00\x08\x00\x78\xd5\x00\x00\x3c\x02\x02\x00\x02\x00\x02\x00\x02\x02\x01\x00\x01\x00\x01\x00\x01\x11\x00\x63\x04\x80\x1e\x03\x24\x04\xd2\x04\xd2\x00\x12\xe5\x64\x4d\x65\x73\x73\x61\x67\x65\x20\x30\x00\x9c\x37'
        a = self.dissect(str)
        log.debug(a.show())
        self.assertEqual(a[IPv6].src, 'aaaa::202:2:2:2')
        self.assertEqual(a[IPv6].dst, 'aaaa::201:1:1:1')
        self.assertEqual(a[IPv6ExtHdrHopByHop].nh, 17)
        self.assertEqual(a[RPLOption].O, 1)
        self.assertEqual(a[RPLOption].rank, 0x0324)
        self.assertEqual(a[UDP].sport, 1234)
        self.assertEqual(a[UDP].dport, 1234)



if __name__ == "__main__":
    logging.basicConfig( stream=sys.stderr )
    logging.getLogger('test_logger').setLevel(logging.DEBUG)
    unittest.main()



