import unittest
from scapy.all import *

class RPLSourceRouteHeader(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(IPv6ExtHdrRPLSourceRouting()),
                         b'\x3b\x02\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        a = IPv6ExtHdrRPLSourceRouting(CmprI = 8,
                                       CmprE = 15,
                                       addresses = ["aaaa::2", "aaaa::3"],
                                       last = "aaaa::4")
        self.assertEqual(bytes(a),
                         b'\x3b\x03\x03\x03\x8f\x70\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x04\x00\x00\x00\x00\x00\x00\x00')

    def test_basic_dissection(self):
        a = IPv6ExtHdrRPLSourceRouting(b'\x3b\x02\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.len == 2 and
                        a.type == 3 and
                        a.segleft == 1 and
                        a.last == "::")

    def test_dissection_with_specific_values(self):
        a = IPv6(b'\x60\x00\x00\x00\x00\x72\x2b\x3f\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x08\x00\x08\x00\x08\x00\x08\x29\x06\x03\x02\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x07\x00\x07\x00\x07\x00\x07\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x04\x00\x04\x00\x04\x00\x04\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x01\x00\x01\x00\x01\x00\x01')
        self.assertTrue(a[IPv6].nh == 43 and
                        a[IPv6ExtHdrRPLSourceRouting].type == 3 and
                        a[IPv6ExtHdrRPLSourceRouting].addresses[0] == "aaaa::207:7:7:7" and
                        a[IPv6ExtHdrRPLSourceRouting].addresses[1] == "aaaa::204:4:4:4" and
                        a[IPv6ExtHdrRPLSourceRouting].last == "aaaa::201:1:1:1")

    def test_dissection_with_specific_values2(self):
        a = IPv6(b'\x60\x00\x00\x00\x00\x72\x2b\x3f\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x08\x00\x08\x00\x08\x00\x08\x29\x03\x03\x02\x88\x00\x00\x00\x02\x07\x00\x07\x00\x07\x00\x07\x02\x04\x00\x04\x00\x04\x00\x04\x02\x01\x00\x01\x00\x01\x00\x01')
        self.assertTrue(a[IPv6].nh == 43 and
                        a[IPv6ExtHdrRPLSourceRouting].type == 3 and
                        a[IPv6ExtHdrRPLSourceRouting].addresses[0] == "aaaa::207:7:7:7" and
                        a[IPv6ExtHdrRPLSourceRouting].addresses[1] == "aaaa::204:4:4:4" and
                        a[IPv6ExtHdrRPLSourceRouting].last == "aaaa::201:1:1:1")

    def test_dissection_with_specific_values3(self):
        a = IPv6(b'\x60\x00\x00\x00\x00\x72\x2b\x3f\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x08\x00\x08\x00\x08\x00\x08\x29\x03\x03\x02\x8f\x70\x00\x00\x02\x07\x00\x07\x00\x07\x00\x07\x02\x04\x00\x04\x00\x04\x00\x04\x01\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a[IPv6].nh == 43 and
                        a[IPv6ExtHdrRPLSourceRouting].type == 3 and
                        a[IPv6ExtHdrRPLSourceRouting].addresses[0] == "aaaa::207:7:7:7" and
                        a[IPv6ExtHdrRPLSourceRouting].addresses[1] == "aaaa::204:4:4:4" and
                        a[IPv6ExtHdrRPLSourceRouting].last == "aaaa::208:8:8:1")
