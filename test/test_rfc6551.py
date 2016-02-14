import unittest
from scapy.all import *

class NodeStateAndAttribute(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(RPLMetricNSA()),
                         b'\x01\x00\x00\x02\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(RPLMetricNSA(P = 1,
                                            C = 1,
                                            O = 1,
                                            R = 1,
                                            A = 3,
                                            prec = 15,
                                            a = 1,
                                            o = 1)),
                         b'\x01\x07\xbf\x02\x00\x03')

    def test_basic_dissection(self):
        a = RPLMetricNSA(b'\x01\x00\x00\x02\x00\x00')
        self.assertTrue(a.type == 1 and
                        a.reserved1 == 0 and
                        a.P == 0 and
                        a.C == 0 and
                        a.O == 0 and
                        a.R == 0 and
                        a.A == 0 and
                        a.prec == 0 and
                        a.len == 2 and
                        a.reserved2 == 0 and
                        a.flags == 0 and
                        a.a == 0 and
                        a.o == 0)

    def test_dissection_with_specific_values(self):
        a = RPLMetricNSA(P = 1,
                         C = 1,
                         O = 1,
                         R = 1,
                         A = 3,
                         prec = 15,
                         a = 1,
                         o = 1)
        self.assertTrue(a.type == 1 and
                        a.reserved1 == 0 and
                        a.P == 1 and
                        a.C == 1 and
                        a.O == 1 and
                        a.R == 1 and
                        a.A == 3 and
                        a.prec == 15 and
                        a.len == 2 and
                        a.reserved2 == 0 and
                        a.flags == 0 and
                        a.a == 1 and
                        a.o == 1)

class NodeEnergy(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(RPLMetricNE()),
                         b'\x02\x00\x00\x02\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(RPLMetricNE(I = 1,
                                           T = 2,
                                           E = 1,
                                           E_E = 100)),
                         b'\x02\x00\x00\x02\x0d\x64')


    def test_basic_dissection(self):
        a = RPLMetricNE(b'\x02\x00\x00\x02\x00\x00')
        self.assertTrue(a.flags == 0 and
                        a.I == 0 and
                        a.T == 0 and
                        a.E == 0 and
                        a.E_E == 0)

    def test_dissection_with_specific_values(self):
        a = RPLMetricNE(b'\x02\x00\x00\x02\x0d\x64')
        self.assertTrue(a.flags == 0 and
                        a.I == 1 and
                        a.T == 2 and
                        a.E == 1 and
                        a.E_E == 100)

class HopCount(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(RPLMetricHP()),
                         b'\x03\x00\x00\x02\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(RPLMetricHP(hopcount = 255)),
                         b'\x03\x00\x00\x02\x00\xff')

    def test_basic_dissection(self):
        a = RPLMetricHP(b'\x03\x00\x00\x02\x00\x00')
        self.assertTrue(a.hopcount == 0)

    def test_dissection_with_specific_values(self):
        a = RPLMetricHP(b'\x03\x00\x00\x02\x00\xff')
        self.assertTrue(a.hopcount == 255)

class Throughput(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(RPLMetricThroughput()),
                         b'\x04\x00\x00\x04\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(RPLMetricThroughput(throughput = 100 * 1000)),
                         b'\x04\x00\x00\x04\x00\x01\x86\xa0')

    def test_basic_dissection(self):
        a = RPLMetricThroughput(b'\x04\x00\x00\x04\x00\x00\x00\x00')
        self.assertTrue(a.throughput == 0)

    def test_dissection_with_specific_values(self):
        a = RPLMetricThroughput(b'\x04\x00\x00\x04\x00\x01\x86\xa0')
        self.assertTrue(a.throughput == 100 * 1000)

class Latency(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(RPLMetricLatency()),
                         b'\x05\x00\x00\x04\x00\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(RPLMetricLatency(latency = 0xdeadbeef)),
                         b'\x05\x00\x00\x04\xde\xad\xbe\xef')

    def test_basic_dissection(self):
        a = RPLMetricLatency(b'\x05\x00\x00\x04\x00\x00\x00\x00')
        self.assertTrue(a.latency == 0)

    def test_dissection_with_specific_values(self):
        a = RPLMetricLatency(b'\x05\x00\x00\x04\xde\xad\xbe\xef')
        self.assertTrue(a.latency == 0xdeadbeef)

class LinkQualityLevelReliability(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(RPLMetricLQL()),
                         b'\x06\x00\x00\x02\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(RPLMetricLQL(lql =
                                            [RPLLQLType1(val = 7,
                                                         counter = 31)])),
                         b'\x06\x00\x00\x02\x00\xff')

    def test_instantiation_with_specific_values2(self):
        self.assertEqual(bytes(RPLMetricLQL(lql =
                                            [RPLLQLType1(val = 7, counter = 31),
                                             RPLLQLType1(val = 7, counter = 31)
                                         ])),
                         b'\x06\x00\x00\x03\x00\xff\xff')

    def test_instantiation_with_specific_values2(self):
        self.assertEqual(bytes(RPLMetricLQL(len = 3)),
                         b'\x06\x00\x00\x03\x00\x00')

    def test_basic_dissection(self):
        a = RPLMetricLQL(b'\x06\x00\x00\x02\x00\x00')
        self.assertTrue(a.lql[0].val == 0 and a.lql[0].counter == 0)

    def test_dissection_with_specific_values(self):
        a = RPLMetricLQL(b'\x06\x00\x00\x02\x00\xff')
        self.assertTrue(a.lql[0].val == 7 and a.lql[0].counter == 31)

    def test_dissection_with_specific_values2(self):
        a = RPLMetricLQL(b'\x06\x00\x00\x03\x00\xff\xff')
        self.assertTrue(a.lql[1].val == 7 and a.lql[1].counter == 31)


class ETXReliability(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(RPLMetricETX()),
                         b'\x07\x00\x00\x02\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(RPLMetricETX(etx = 65535)),
                         b'\x07\x00\x00\x02\xff\xff')

    def test_basic_dissection(self):
        a = RPLMetricETX(b'\x07\x00\x00\x02\x00\x00')
        self.assertTrue(a.etx == 0)

    def test_dissection_with_specific_values(self):
        a = RPLMetricETX(b'\x07\x00\x00\x02\x00\xff')
        self.assertTrue(a.etx == 255)

class LinkColor(unittest.TestCase):
    def test_basic_instantiation(self):
        self.assertEqual(bytes(RPLMetricLC()),
                         b'\x08\x00\x00\x03\x00\x00\x00')

    def test_instantiation_with_specific_values(self):
        self.assertEqual(bytes(RPLMetricLC(C = 0,
                                           lc = [RPLLCType1(linkcolor = 1000,
                                                            counter = 63)])),
                         b'\x08\x00\x00\x03\x00\xfa\x3f')

    def test_instantiation_with_specific_values2(self):
        self.assertEqual(bytes(RPLMetricLC(C = 0,
                                           lc = [RPLLCType1(linkcolor = 1000,
                                                            counter = 63),
                                                 RPLLCType1(linkcolor = 1000,
                                                            counter = 63)])),
                         b'\x08\x00\x00\x03\x00\xfa\x3f\xfa\x3f')

    def test_instantiation_with_specific_values3(self):
        self.assertEqual(bytes(RPLMetricLC(C = 1,
                                           lc = [RPLLCType2(linkcolor = 1000,
                                                            I = 1)])),
                         b'\x08\x02\x00\x03\x00\xfa\x01')

    def test_instantiation_with_specific_values4(self):
        self.assertEqual(bytes(RPLMetricLC(C = 1,
                                           lc = [RPLLCType2(linkcolor = 1000,
                                                            I = 1),
                                                 RPLLCType2(linkcolor = 1000,
                                                            I = 1)])),
                         b'\x08\x02\x00\x03\x00\xfa\x01\xfa\x01')

    def test_basic_dissection(self):
        a = RPLMetricLC(b'\x08\x00\x00\x03\x00\x00\x00')
        self.assertTrue(a.C == 0 and
                        a.lc[0].linkcolor == 0 and
                        a.lc[0].counter == 0)

    def test_dissection_with_specific_values(self):
        a = RPLMetricLC(b'\x08\x00\x00\x03\x00\xfa\x3f')
        self.assertTrue(a.C == 0 and
                        a.lc[0].linkcolor == 1000 and
                        a.lc[0].counter == 63)

    def test_dissection_with_specific_values2(self):
        a = RPLMetricLC(b'\x08\x00\x00\x05\x00\xfa\x3f\xfa\x3f')
        self.assertTrue(a.C == 0 and
                        a.lc[1].linkcolor == 1000 and
                        a.lc[1].counter == 63)

    def test_dissection_with_specific_values3(self):
        a = RPLMetricLC(b'\x08\x02\x00\x03\x00\xfa\x01')
        self.assertTrue(a.C == 1 and
                        a.lc[0].linkcolor == 1000 and
                        a.lc[0].I == 1)

    def test_dissection_with_specific_values4(self):
        a = RPLMetricLC(b'\x08\x02\x00\x05\x00\xfa\x01\xfa\x01')
        self.assertTrue(a.C == 1 and
                        a.lc[1].linkcolor == 1000 and
                        a.lc[1].I == 1)
