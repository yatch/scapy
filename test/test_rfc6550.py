import unittest
from scapy.all import *

class Pad1(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptPad1()),
                         b'\x00')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptPad1(b'\00')
        self.assertTrue(a.type == 0)

class PadN(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptPadN()),
                         b'\x01\x00')

    def test_instantiation_autofill_padding(self):
        self.assertEqual(bytes(ICMPv6RPLOptPadN(len = 5)),
                         b'\x01\x05\x00\x00\x00\x00\x00')

    def test_instantiation_autofill_len(self):
        self.assertEqual(bytes(ICMPv6RPLOptPadN(padding = b'\x00\x00\x00\x00\x00')),
                         b'\x01\x05\x00\x00\x00\x00\x00')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptPadN(b'\x01\x00')
        self.assertTrue(a.type == 1 and a.len == 0)

    def test_dissection_with_specific_values(self):
        a = ICMPv6RPLOptPadN(b'\x01\x05\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 1 and
                        a.len == 5 and
                        a.padding == b'\x00\x00\x00\x00\x00')

class DAGMetricContainer(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptDAGMetricContainer()),
                         b'\x02\x00')

    def test_instantiation_with_specific_values(self):
        a = ICMPv6RPLOptDAGMetricContainer()/RPLMetricNSA()
        self.assertEqual(bytes(a),
                         b'\x02\x06\x01\x00\x00\x02\x00\x00')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptDAGMetricContainer(b'\x02\x00')
        self.assertTrue(a.type == 2 and a.len == 0)


    def test_dissection_with_specifc_values(self):
        a = ICMPv6RPLOptDAGMetricContainer(b'\x02\x06\x01\x00\x00\x02\x00\x00')
        self.assertTrue(a[ICMPv6RPLOptDAGMetricContainer].type == 2 and
                        a[ICMPv6RPLOptDAGMetricContainer].len == 6 and
                        a[RPLMetricNSA].type == 1 and
                        a[RPLMetricNSA].len == 2)
        self.assertTrue(a[0].type == 2 and
                        a[0].len == 6 and
                        a[1].type == 1 and
                        a[1].len == 2)

    def test_dissection_with_specifc_values2(self):
        a = ICMPv6RPLOptDAGMetricContainer(b'\x02\x0a\x08\x02\x00\x05\x00\xfa\x01\xfa\x01')
        self.assertTrue(a[ICMPv6RPLOptDAGMetricContainer].type == 2 and
                        a[ICMPv6RPLOptDAGMetricContainer].len == 10 and
                        a[RPLMetricLC].type == 8 and
                        a[RPLMetricLC].len == 5 and
                        a[RPLMetricLC].lc[0].link_color == 1000 and
                        a[RPLMetricLC].lc[0].i == 1 and
                        a[RPLMetricLC].lc[1].link_color == 1000 and
                        a[RPLMetricLC].lc[1].i == 1)

        self.assertTrue(a[0].type == 2 and
                        a[0].len == 10 and
                        a[1].type == 8 and
                        a[1].len == 5 and
                        a[1].lc[0].link_color == 1000 and
                        a[1].lc[0].i == 1 and
                        a[1].lc[1].link_color == 1000 and
                        a[1].lc[1].i == 1)

class RouteInformation(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptRouteInformation()),
                         b'\x03\x06\x00\x00\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        a = ICMPv6RPLOptRouteInformation(plen = 64,
                                         prf = 3,
                                         route_lifetime = 0x11223344,
                                         prefix = "2001:db8::1")
        self.assertEqual(bytes(a),
                         b'\x03\x16\x40\x18\x11\x22\x33\x44\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')

    def test_instantiation_with_specific_values2(self):
        a = ICMPv6RPLOptRouteInformation(plen = 96,
                                         prf = 3,
                                         route_lifetime = 0x11223344,
                                         prefix = "2001:db8::/96")
        self.assertEqual(bytes(a),
                         b'\x03\x12\x60\x18\x11\x22\x33\x44\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptRouteInformation(b'\x03\x06\x00\x00\00\00\00\00')
        self.assertTrue(a.type == 3 and
                        a.len == 6 and
                        a.route_lifetime == 0)

    def test_dissection_with_specific_values(self):
        a = ICMPv6RPLOptRouteInformation(b'\x03\x16\x40\x18\x11\x22\x33\x44\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
        self.assertTrue(a.type == 3 and
                        a.len == 22 and
                        a.plen == 64 and
                        a.prf == 3 and
                        a.route_lifetime == 0x11223344 and
                        a.prefix == "2001:db8::1/128")


    def test_dissection_with_specific_values2(self):
        a = ICMPv6RPLOptRouteInformation(b'\x03\x12\x60\x18\x11\x22\x33\x44\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 3 and
                        a.len == 18 and
                        a.plen == 96 and
                        a.prf == 3 and
                        a.route_lifetime == 0x11223344 and
                        a.prefix == "2001:db8::/96")

class DODAGConfiguration(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptDODAGConfiguration()),
                         b'\x04\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        a = ICMPv6RPLOptDODAGConfiguration(A = 1,
                                           pcs = 7,
                                           dio_int_double = 255,
                                           dio_int_min = 255,
                                           dio_redun = 255,
                                           max_rank_increase = 65535,
                                           min_hop_increase = 65535,
                                           ocp = 65535,
                                           def_lifetime = 255,
                                           lifetime_unit = 65535)
        self.assertEqual(bytes(a),
                         b'\x04\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptDODAGConfiguration(b'\x04\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 4 and
                        a.len == 14)

    def test_dissection_with_specifc_values(self):
        a = ICMPv6RPLOptDODAGConfiguration(b'\x04\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff')
        self.assertTrue(a.A == 1 and
                        a.pcs == 7 and
                        a.dio_int_double == 255 and
                        a.dio_int_min == 255 and
                        a.dio_redun == 255 and
                        a.max_rank_increase == 65535 and
                        a.min_hop_increase == 65535 and
                        a.ocp == 65535 and
                        a.def_lifetime == 255 and
                        a.lifetime_unit == 65535)

class RPLTarget(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptRPLTarget()),
                         b'\x05\x02\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(ICMPv6RPLOptRPLTarget(prefix_length = 64,
                                                     target_prefix = "2001:db8::1/128")),
                         b'\x05\x12\x00\x40\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptRPLTarget(b'\x05\x02\x00\x00')
        self.assertTrue(a.type == 5 and
                        a.len == 2)

    def test_dissection_with_specifc_values(self):
        a = ICMPv6RPLOptRPLTarget(b'\x05\x12\x00\x40\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
        print(a.target_prefix)
        self.assertTrue(a.len == 18 and
                        a.prefix_length == 64 and
                        a.target_prefix == "2001:db8::1/128")

class TransitInformation(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptTransitInformation()),
                         b'\x06\x04\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        a = ICMPv6RPLOptTransitInformation(E = 1,
                                           path_control = 255,
                                           path_sequence = 255,
                                           path_lifetime = 255,
                                           parent_address = "2001:db8::1/128")
        self.assertEqual(bytes(a),
                         b'\x06\x14\x80\xff\xff\xff\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptTransitInformation(b'\x06\x04\x00\x00\x00\x00')
        self.assertTrue(a.type == 6 and
                        a.len == 4)

    def test_dissection_with_specific_values(self):
        a = ICMPv6RPLOptTransitInformation(b'\x06\x14\x80\xff\xff\xff\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
        self.assertTrue(a.len == 20 and
                        a.E == 1 and
                        a.path_control == 255 and
                        a.path_sequence == 255 and
                        a.path_lifetime == 255 and
                        a.parent_address == "2001:db8::1/128")

class SolicitedInformation(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptSolicitedInformation()),
                         b'\x07\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_instantiation_specific_values(self):
        a = ICMPv6RPLOptSolicitedInformation(rpl_instance_id = 255,
                                             V = 1,
                                             I = 1,
                                             D = 1,
                                             dodagid = "2001:db8::1",
                                             version_number = 255)
        self.assertEqual(bytes(a),
                         b'\x07\x13\xff\xe0\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptSolicitedInformation(b'\x07\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 7 and
                        a.len == 19)

    def test_dissection_with_specific_values(self):
        a = ICMPv6RPLOptSolicitedInformation(b'\x07\x13\xff\xe0\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff')
        self.assertTrue(a.rpl_instance_id == 255 and
                        a.V == 1 and
                        a.I == 1 and
                        a.D == 1 and
                        a.dodagid == "2001:db8::1" and
                        a.version_number == 255)

class PrefixInformation(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptPrefixInformation()),
                         b'\x08\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        a = ICMPv6RPLOptPrefixInformation(prefix_length = 64,
                                          L = 1,
                                          A = 1,
                                          R = 1,
                                          valid_lifetime = 4294967295,
                                          preferred_lifetime = 4294967295,
                                          prefix = "2001:db8::1")
        self.assertEqual(bytes(a),
                         b'\x08\x1e\x40\xe0\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptPrefixInformation(b'\x08\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertTrue(a.type == 8 and
                        a.len == 30)

    def test_dissection_with_specifc_values(self):
        a = ICMPv6RPLOptPrefixInformation(b'\x08\x1e\x40\xe0\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
        self.assertTrue(a.prefix_length == 64 and
                        a.L == 1 and
                        a.A == 1 and
                        a.R == 1 and
                        a.valid_lifetime == 4294967295 and
                        a.preferred_lifetime == 4294967295 and
                        a.prefix == "2001:db8::1")

class RPLTargetDescriptor(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(ICMPv6RPLOptRPLTargetDescriptor()),
                         b'\x09\x04\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(ICMPv6RPLOptRPLTargetDescriptor(descriptor = 0x11223344)),
                         b'\x09\x04\x11\x22\x33\x44')

    def test_basic_dissection(self):
        a = ICMPv6RPLOptRPLTargetDescriptor(b'\x09\x04\x00\x00\x00\x00')
        self.assertTrue(a.type == 9 and
                        a.len == 4)

    def test_dissection_with_specific_values(self):
        a = ICMPv6RPLOptRPLTargetDescriptor(b'\x09\x04\x11\x22\x33\x44')
        self.assertTrue(a.descriptor == 0x11223344)
