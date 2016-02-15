import unittest
from scapy.all import *

class RPLHopByHopOption(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(RPLOption()),
                         b'\x63\x04\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(RPLOption(O = 1,
                                         R = 1,
                                         F = 1,
                                         instanceid = 0x22,
                                         rank = 0x3344)),
                         b'\x63\x04\xe0\x22\x33\x44')

    def test_basic_dissection(self):
        a = RPLOption(b'\x63\x04\x00\x00\x00\x00')
        self.assertTrue(a.otype == 0x63 and
                        a.optlen == 4)

    def test_dissection_with_specific_values(self):
        a = IPv6(b'\x60\x00\x00\x00\x00\x4a\x00\x40\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x06\x00\x06\x00\x06\x00\x06\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x03\x00\x03\x00\x03\x00\x03\x3a\x00\x63\x04\x00\x1e\x02\x59')
        self.assertTrue(a[RPLOption].instanceid == 0x1e and
                        a[RPLOption].rank == 0x0259)
