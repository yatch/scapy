import unittest
from scapy.all import *

class AddressRegistrationOption(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6NDOptARO()),
                         b'\x21\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        a = ICMPv6NDOptARO(registration_lifetime = 6000,
                           eui_64 = "00:02:00:02:00:02:00:02")
        self.assertTrue(bytes(a),
                        b'\x21\x02\x00\x00\x00\x00\x17\70\x00\x02\x00\x02\x00\x02\x00\x02')

    def test_basic_dissection(self):
        a = ICMPv6NDOptARO(b'\x21\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 33 and
                        a.len == 2 and
                        a.eui_64 == "00:00:00:00:00:00:00:00")

    def test_dissection_with_specific_values(self):
        a = IPv6(b'\x60\x00\x00\x00\x00\x38\x3a\xff\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x02\x00\x02\x00\x02\x00\x02\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x05\x00\x05\x00\x05\x00\x05\x87\x00\x38\xd9\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x05\x00\x05\x00\x05\x00\x05\x01\x02\x00\x02\x00\x02\x00\x02\x00\x02\x00\x00\x00\x00\x00\x00\x21\x02\x00\x00\x00\x00\x17\x70\x00\x02\x00\x02\x00\x02\x00\x02')
        self.assertTrue(a[ICMPv6NDOptARO].type == 33 and
                        a[ICMPv6NDOptARO].len == 2 and
                        a[ICMPv6NDOptARO].registration_lifetime == 6000 and
                        a.eui_64 == "00:02:00:02:00:02:00:02")

class SixLoWPANContextOption(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6NDOpt6CO()),
                         b'\x22\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_basic_dissection(self):
        a = ICMPv6NDOpt6CO(b'\x22\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 34 and
                        a.len == 2 and
                        a.context_prefix == "::/64")

    def test_basic_dissection2(self):
        a = ICMPv6NDOpt6CO(b'\x22\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 34 and
                        a.len == 3 and
                        a.context_prefix == "::/128")

class AuthoritativeBorderRouterOption(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6NDOptABRO()),
                         b'\x23\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_basic_dissection(self):
        a = ICMPv6NDOptABRO(b'\x23\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 35 and
                        a.len == 3 and
                        a.sixlbr_address == "::")

class DuplicateAddressRequest(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6ND_DAR()),
                         b'\x9d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_basci_dissection(self):
        a = ICMPv6ND_DAR(b'\x9d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 157 and
                        a.eui_64 == "00:00:00:00:00:00:00:00" and
                        a.registered_address == "::")


class DuplicateAddressConfirmation(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6ND_DAC()),
                         b'\x9e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_basci_dissection(self):
        a = ICMPv6ND_DAC(b'\x9e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 158 and
                        a.eui_64 == "00:00:00:00:00:00:00:00" and
                        a.registered_address == "::")
