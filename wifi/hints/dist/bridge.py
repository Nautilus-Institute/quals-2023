#!/usr/bin/env python3
"""
WiFi Client
"""
import random
import hmac, hashlib
import os
import fcntl
import sys

from itertools import count
import pyaes
import threading
import binascii
import subprocess


from scapy.layers.eap import EAPOL
from scapy.layers.dot11 import *
from scapy.layers.l2 import LLC, SNAP
from scapy.layers.dhcp import *
from scapy.layers.inet import *
from scapy.fields import *
from scapy.arch import str2mac, get_if_raw_hwaddr

from time import time, sleep

#agents did not manage to exfil this file
#from gost import gen_psk

class Level:
    CRITICAL = 0
    WARNING = 1
    INFO = 2
    DEBUG = 3
    BLOAT = 4


VERBOSITY = Level.BLOAT


def printd(string, level=Level.INFO):
    if VERBOSITY >= level:
        print(string, file=sys.stderr)

### Constants

# CCMP, PSK=WPA2
eRSN = Dot11EltRSN(
    ID=48,
    len=20,
    version=1,
    mfp_required=0,
    mfp_capable=0,
    group_cipher_suite=RSNCipherSuite(cipher="CCMP-128"),
    nb_pairwise_cipher_suites=1,
    pairwise_cipher_suites=RSNCipherSuite(cipher="CCMP-128"),
    nb_akm_suites=1,
    akm_suites=AKMSuite(suite="PSK"),
)
RSN = eRSN.build()

AP_RATES = b"\x0c\x12\x18\x24\x30\x48\x60\x6c"

DOT11_MTU = 4096

DOT11_TYPE_MANAGEMENT = 0
DOT11_TYPE_CONTROL = 1
DOT11_TYPE_DATA = 2

DOT11_SUBTYPE_DATA = 0x00
DOT11_SUBTYPE_PROBE_REQ = 0x04
DOT11_SUBTYPE_AUTH_REQ = 0x0B
DOT11_SUBTYPE_ASSOC_REQ = 0x00
DOT11_SUBTYPE_REASSOC_REQ = 0x02
DOT11_SUBTYPE_QOS_DATA = 0x28

# Ripped from scapy-latest with fixes
class EAPOL_KEY(Packet):
    name = "EAPOL_KEY"
    fields_desc = [
        ByteEnumField("key_descriptor_type", 1, {1: "RC4", 2: "RSN"}),
        # Key Information
        BitField("reserved2", 0, 2),
        BitField("smk_message", 0, 1),
        BitField("encrypted_key_data", 0, 1),
        BitField("request", 0, 1),
        BitField("error", 0, 1),
        BitField("secure", 0, 1),
        BitField("has_key_mic", 1, 1),
        BitField("key_ack", 0, 1),
        BitField("install", 0, 1),
        BitField("key_index", 0, 2),
        BitEnumField("key_type", 0, 1, {0: "Group/SMK", 1: "Pairwise"}),
        BitEnumField(
            "key_descriptor_type_version",
            0,
            3,
            {1: "HMAC-MD5+ARC4", 2: "HMAC-SHA1-128+AES-128", 3: "AES-128-CMAC+AES-128"},
        ),
        #
        LenField("key_length", None, "H"),
        LongField("key_replay_counter", 0),
        XStrFixedLenField("key_nonce", b"\x00" * 32, 32),
        XStrFixedLenField("key_iv", b"\x00" * 16, 16),
        XStrFixedLenField("key_rsc", b"\x00" * 8, 8),
        XStrFixedLenField("key_id", b"\x00" * 8, 8),
        XStrFixedLenField("key_mic", b"\x00" * 16, 16),  # XXX size can be 24
        LenField("wpa_key_length", None, "H"),
        ConditionalField(
            XStrLenField(
                "key", b"\x00" * 16, length_from=lambda pkt: pkt.wpa_key_length
            ),
            lambda pkt: pkt.wpa_key_length and pkt.wpa_key_length > 0,
        ),
    ]

    def extract_padding(self, s):
        return s[: self.key_length], s[self.key_length :]

    def hashret(self):
        return struct.pack("!B", self.type) + self.payload.hashret()

    def answers(self, other):
        if (
            isinstance(other, EAPOL_KEY)
            and other.descriptor_type == self.descriptor_type
        ):
            return 1
        return 0


def pad_key_data(plain):
    pad_len = len(plain) % 8
    if pad_len:
        plain += b"\xdd" * (8 - pad_len)
    return plain


#### Helpers from maty van hoef's libwifi
def ccmp_pn(pn):
    return pn.PN0 + (pn.PN1 << 8) + (pn.PN2 << 16) + (pn.PN3 << 24)


def addr2bin(addr):
    return binascii.a2b_hex(addr.replace(":", ""))


def ccmp_get_nonce(priority, addr, pn):
    """
    CCMP nonce = 1 byte priority, 6 byte sender addr, 6 byte PN.
    """
    return struct.pack("B", priority) + addr2bin(addr) + pn2bin(pn)


def ccmp_get_aad(p, amsdu_spp=False):
    # FC field with masked values
    fc = raw(p)[:2]
    # data mask
    fc = struct.pack("<BB", fc[0] & 0x8F, fc[1] & 0xC7)

    # Sequence number is masked, but fragment number is included
    sc = struct.pack("<H", p.SC & 0xF)

    addr1 = addr2bin(p.addr1)
    addr2 = addr2bin(p.addr2)
    addr3 = addr2bin(p.addr3)
    aad = fc + addr1 + addr2 + addr3 + sc
    if Dot11QoS in p:
        if not amsdu_spp:
            # Everything except the TID is masked
            aad += struct.pack("<H", p[Dot11QoS].TID)
        else:
            # TODO: Mask unrelated fields
            aad += raw(p[Dot11QoS])[:2]
    return aad


def pn2bytes(pn):
    pn_bytes = [0] * 6
    for i in range(6):
        pn_bytes[i] = pn & 0xFF
        pn >>= 8
    return pn_bytes


def pn2bin(pn):
    return struct.pack(">Q", pn)[2:]


def dot11_get_seqnum(p):
    return p.SC >> 4


def dot11_is_encrypted_data(p):
    # All these different cases are explicitly tested to handle older scapy versions
    return (
        (p.FCfield & 0x40)
        or Dot11CCMP in p
        or Dot11TKIP in p
        or Dot11WEP in p
        or Dot11Encrypted in p
    )

def payload_to_iv(payload):
    iv0 = payload[0]
    iv1 = payload[1]
    wepdata = payload[4:8]

    # FIXME: Only CCMP is supported (TKIP uses a different IV structure)
    return orb(iv0) + (orb(iv1) << 8) + (struct.unpack(">I", wepdata)[0] << 16)


def dot11_get_priority(p):
    if not Dot11QoS in p:
        return 0
    return p[Dot11QoS].TID


def dot11_get_iv(p):
    # The simple and default case
    if Dot11CCMP in p:
        payload = raw(p[Dot11CCMP])
        return payload_to_iv(payload)
    # Scapy uses Dot11Encrypted if it couldn't determine how the frame was encrypted. Assume CCMP.
    elif Dot11Encrypted in p:
        payload = raw(p[Dot11Encrypted])
        return payload_to_iv(payload)
    # Couldn't determine the IV
    return None


def is_broadcast(ether):
    return ether == "ff:ff:ff:ff:ff:ff"

def is_multicast(ether):
    return int(ether[0:2], 16) & 0x1 == 1

### CCMP wrapper. See RFC 3610
class CCMPCrypto:
    @staticmethod
    def cbc_mac(key, plaintext, aad, nonce, iv=b"\x00" * 16, mac_len=8):
        assert len(key) == len(iv) == 16  # aes-128
        assert len(nonce) == 13
        iv = int.from_bytes(iv, byteorder="big")
        assert len(aad) < (2**16 - 2**8)

        q = L = 2
        Mp = (mac_len - 2) // 2
        assert q == L
        has_aad = len(aad) > 0
        flags = 64 * has_aad + 8 * Mp + (q - 1)
        b_0 = struct.pack("B", flags) + nonce + struct.pack(">H", len(plaintext))
        assert len(b_0) == 16

        a = struct.pack(">H", len(aad)) + aad
        if len(a) % 16 != 0:
            a += b"\x00" * (16 - len(a) % 16)
        blocks = b_0 + a
        blocks += plaintext

        if len(blocks) % 16 != 0:
            blocks += b"\x00" * (16 - len(blocks) % 16)

        encrypt = pyaes.AESModeOfOperationECB(key).encrypt
        prev = iv
        for i in range(0, len(blocks), 16):
            inblock = int.from_bytes(blocks[i : i + 16], byteorder="big")
            outblock = encrypt(int.to_bytes(inblock ^ prev, length=16, byteorder="big"))
            prev = int.from_bytes(outblock, byteorder="big")

        # xor tag with E(0) construction using nonce in CTR mode
        xn = struct.pack("B", q - 1) + nonce + b"\x00" * L
        ctr_nonce = int.from_bytes(xn, byteorder="big")
        xctr = pyaes.AESModeOfOperationCTR(
            key, counter=pyaes.Counter(ctr_nonce)
        ).encrypt
        xs0 = xctr(b"\x00" * 16)
        s_0 = int.from_bytes(xs0, byteorder="big")

        return int.to_bytes(s_0 ^ prev, length=16, byteorder="big")[:mac_len]

    @staticmethod
    def ctr_encrypt(key, nonce, plaintext, q=2, L=2):
        xn = struct.pack("B", q - 1) + nonce + b"\x00" * L
        ctr_nonce = int.from_bytes(xn, byteorder="big")
        xctr = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(ctr_nonce))
        # start ctr
        _ = xctr.encrypt(b"\x00" * 16)
        return xctr.encrypt(plaintext)

    @staticmethod
    def run_ccmp_encrypt(key, nonce, aad, plaintext):
        tag = CCMPCrypto.cbc_mac(key, plaintext, aad, nonce)
        encrypted = CCMPCrypto.ctr_encrypt(key, nonce, plaintext)
        return encrypted, tag

    @staticmethod
    def run_ccmp_decrypt(key, nonce, aad, ciphertext, known_tag):
        valid = False
        # ctr encrypt/decrypt is symmetric
        plaintext = CCMPCrypto.ctr_encrypt(key, nonce, ciphertext)
        tag = CCMPCrypto.cbc_mac(key, plaintext, aad, nonce)
        # constant time compare validity of tag
        valid = hmac.compare_digest(tag, known_tag)
        return plaintext, valid

    @staticmethod
    def test():
        k = b"k" * 16
        a = b"a" * 22
        n = b"n" * 13
        p = b"P" * 128
        cipher, tag = CCMPCrypto.run_ccmp_encrypt(k, n, a, p)
        p2, verified = CCMPCrypto.run_ccmp_decrypt(k, n, a, cipher, tag)
        assert p == p2
        assert verified
        return True

def if_hwaddr(iff):
    return str2mac(get_if_raw_hwaddr(iff)[1])

def aes_wrap(kek, plain):
    n = len(plain) // 8
    a = 0xA6A6A6A6A6A6A6A6
    enc = pyaes.AESModeOfOperationECB(kek).encrypt
    r = [plain[i * 8 : (i + 1) * 8] for i in range(0, n)]
    for j in range(6):
        for i in range(1, n + 1):
            b = enc(struct.pack(">Q", a) + r[i - 1])
            a = struct.unpack(">Q", b[:8])[0] ^ (n * j + i)
            r[i - 1] = b[8:]
    return struct.pack(">Q", a) + b"".join(r)

def aes_unwrap(kek, wrapped):
    n = (len(wrapped) // 8) - 1
    #NOTE: R[0] is never accessed, left in for consistency with RFC indices
    r = [None] + [wrapped[i * 8:i * 8 + 8] for i in range(1, n + 1)]
    a = struct.unpack(">Q", wrapped[:8])[0]
    decrypt = pyaes.AESModeOfOperationECB(kek).decrypt
    for j in range(5, -1, -1):  #counting down
        for i in range(n, 0, -1):  #(n, n-1, ..., 1)
            ciphertext = struct.pack(">Q", a ^ (n * j + i)) + r[i]
            B = decrypt(ciphertext)
            a = struct.unpack(">Q", B[:8])[0]
            r[i] = B[8:]
    assert(a == 0xA6A6A6A6A6A6A6A6)
    return b"".join(r[1:])

def customPRF512(key, amac, smac, anonce, snonce):
    """Source https://stackoverflow.com/questions/12018920/"""
    A = b"Pairwise key expansion"
    B = b"".join(sorted([amac, smac]) + sorted([anonce, snonce]))
    num_bytes = 64
    R = b""
    for i in range((num_bytes * 8 + 159) // 160):
        R += hmac.new(key, A + chb(0x00) + B + chb(i), hashlib.sha1).digest()
    return R[:num_bytes]


class Client:

    class BridgeTransmitter(threading.Thread):
        def __init__(self, iface, xmit):
            threading.Thread.__init__(self)
            self.iface = iface
            self.xmit = xmit
            self.daemon = True

        def recv_pkt(self, packet):
            self.xmit(packet, verbose=False)

        def run(self):
            sniff(iface=self.iface, prn=self.recv_pkt, store=0)

    def __init__(self, ssid, psk, mac=None, mode="stdio", iface="wlan0"):
        self.iface = iface
        self.mode = mode
        if self.mode == "iface" or self.mode == "bridge":
            mac = if_hwaddr(iface)
        if not mac:
          raise Exception("Need a mac")
        else:
          self.mac = mac
        self.channel = 1
        self.mutex = threading.Lock()
        self.brx = self.BridgeTransmitter(self.iface, self.sendp)

    def get_radiotap_header(self):
        return RadioTap()

    def run(self):
        self.brx.start()
        if self.mode == "iface":
            sniff(iface=self.iface, prn=self.recv_pkt, store=0)
            return

        assert self.mode == "stdio" or self.mode == "bridge"
        os.set_blocking(sys.stdin.fileno(), False)
        qdata = b""
        while True:
          sleep(0.001)
          data = sys.stdin.buffer.read(65536)
          if data:
              qdata += data
          if len(qdata) > 4:
              wanted = struct.unpack("<L", qdata[:4])[0]
              if len(qdata) + 4 >= wanted:
                  p = RadioTap(qdata[4:4 + wanted])
                  #printd(p.addr1 + " " + p.addr2 + " " + p.addr3)
                  if self.mode == "bridge":
                    sendp(p, iface=self.iface, verbose=False)
                  else:
                    self.recv_pkt(p)
                  qdata = qdata[4 + wanted:]

    def sendp(self, packet, verbose=False):
        if self.mode == "stdio" or self.mode == "bridge":
            x = packet.build()
            sys.stdout.buffer.write(struct.pack("<L", len(x)) + x)
            sys.stdout.buffer.flush()
            return

        assert self.mode == "iface"
        printd('sending packet to ' + self.iface)
        sendp(packet, iface=self.iface, verbose=False)

# run with socat exec:./bridge.py tcp:server:port
if __name__ == "__main__":
    import sys
    data = sys.stdin.buffer.read(len("Ticket please: "))
    printd(data)
    os.set_blocking(sys.stdin.fileno(), False)
    os.set_blocking(sys.stdout.fileno(), False)
    sys.stdout.buffer.write(b"ticket{ticket}\n")
    sys.stdout.buffer.flush()
    sleep(1)
    printd("start")
    client = Client("defcon2023", "defcon2023", mac="02:00:00:00:00:00", mode="bridge", iface="mon0")
    client.run()
