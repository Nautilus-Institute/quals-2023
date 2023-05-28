#!/usr/bin/env python3
"""
Defcon AP based on barely-AP.
Rewrite to support STDIO/STDOUT for running in xinetd.
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
from scapy.layers.l2 import LLC, SNAP, ARP
from scapy.layers.dhcp import *
from scapy.layers.inet import *
from scapy.fields import *
from scapy.arch import str2mac, get_if_raw_hwaddr

from time import time, sleep
from gost import gen_psk

if os.path.exists('/flag.txt'):
    with open('/flag.txt') as f:
        FLAG = f.read()
else:
    FLAG="FLAG{FLAG GOES HERE}"
boats = ["eclipse", "solaris", "axioma", "crescent", "ragnar", "valerie", "sailing yacht a", "the dilbar", "la datcha", "amore vero", "quantum blue", "luna", "triple seven", "le grande bleu", "kosatka"]

global BOAT_IDX
BOAT_IDX = 0
GOST_CODE = open("gost.py").read()

BOATHELP = """BLYAT!
    HELP - This help file
    INFO - Info about the Yacht
    ANTENNA - Activate antenna
    POSITION - Show current Position
    DETONATE -
    CODE - Show code
"""

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

# Abstract fake IP network.
class Network(threading.Thread):
    def __init__(self, bss, ip="10.10.10.1/24"):
        threading.Thread.__init__(self)
        self.bss = bss
        if "/" in ip:
            self.ip = ip.split("/")[0]

        # hack
        self.subnet = '.'.join(self.ip.split('.')[:3])
        self.txq = []
        self.macs = []
        self.data_ready = threading.Condition()

        self.boatip = self.subnet + ".%d" % random.randrange(50,100)
        global BOAT_IDX
        self.boatmac = "45:44:44:00:00:" + "%.2d"%BOAT_IDX
        self.boatport = 2422
        self.boatname = boats[BOAT_IDX]
        self.boat_long = random.uniform(28.9, 40)
        self.boat_latt = random.uniform(41.9, 44.5)
        self.boat_info = "N/A"
        if BOAT_IDX == len(boats)-1:
            self.boat_info = "Vovan's Special Boat"

        printd("boat at %s %s port %d" %(self.boatip, self.boatmac, self.boatport))

    def antenna(self):
        #activate the antenna
        global BOAT_IDX

        if BOAT_IDX + 1 >= len(boats):
            return "[-] No more boats available"

        BOAT_IDX += 1

        self.bss.ap.activate_next()
        return "[+] Activated Radio\n"

    def position(self):
        return "Coordinates: %2.3f 'N %2.3f ' E'\n"%(self.boat_latt, self.boat_long)

    def info(self):
        return "Name: %s\nSTATUS: underway\nIP: %s\nINFO: %s\n"%(self.boatname, self.boatip, self.boat_info)

    def detonate(self):
        if self.boat_info != "N/A":
            return FLAG
        return "kaboom!"

    def code(self):
        return GOST_CODE

    def write(self, packet):
        self.data_ready.acquire()
        self.txq.append(packet)
        self.data_ready.notify()
        self.data_ready.release()

    def transmit(self, deth, packet):
        self.bss.ap.tun_data_incoming(self.bss, deth, packet)

    def input(self, incoming):
        #ip to mac address map
        m = {}
        m[self.ip] = self.bss.mac
        m[self.boatip] = self.boatmac
        for i in range(len(self.macs)):
            m["%s.%d" % (self.subnet, i+1)] = self.macs[i]

        if DHCP in incoming:
            #handle a dhcp packet
            if incoming[UDP].dport == 67:
                if incoming[BOOTP].op == 1:
                    req_type = next(opt[1] for opt in incoming[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')
                    if req_type == 1:
                        self.reply_dhcp_offer(incoming)
                    elif req_type == 3:
                        self.reply_dhcp_ack(incoming)
        elif ARP in incoming:
                if incoming[ARP].sprintf("%ARP.op%") != 'who-has':
                    return
                if incoming.pdst in m:
                    if incoming.pdst in m:
                        d = m[incoming.pdst]
                    else:
                        return
                    reply = ARP(op=2, hwsrc=d, psrc=incoming.pdst, hwdst=incoming.src, pdst=incoming.psrc)
                    go = Ether(dst=incoming.src, src=self.bss.mac) / reply
                    self.transmit(incoming.src, go.build())
        elif ICMP in incoming:
            if incoming[ICMP].type == 8:
                sender_ip = self.ip

                eth_ip_header = Ether(src=self.bss.mac, dst=incoming[Ether].src) \
                   / IP(dst=incoming[IP].src, src=sender_ip) \

                icmp = None
                if incoming[IP].dst not in m:
                    #unknown dst. drop and reply w/ icmp fail
                    icmp = ICMP(type=3, code=1) / incoming.payload.build()[:64]
                else:
                    icmp = ICMP(type=0, seq=incoming[ICMP].seq, id=incoming[ICMP].id) \
                            / incoming[ICMP].load

                    # update sender IP
                    eth_ip_header[IP].src = incoming[IP].dst
                    #choose mac addr of host
                    eth_ip_header[Ether].src = m[incoming[IP].dst]

                reply_packet = eth_ip_header \
                   / icmp
                self.transmit(incoming.src, reply_packet.build())
        elif UDP in incoming:
            eth_ip_header = Ether(src=self.bss.mac, dst=incoming[Ether].src) \
               / IP(dst=incoming[IP].src, src=incoming[IP].dst) \

            icmp = None

            if incoming[IP].dst not in m:
                #unknown dst. drop and reply w/ icmp fail
                icmp = ICMP(type=3, code=1) / incoming.payload.build()[:64]
                eth_ip_header[IP].src = self.ip # no host, send from gateway

            if incoming[UDP].dport != self.boatport or incoming[IP].dst != self.boatip:
                # wrong port
                icmp = ICMP(type=3, code=3) / incoming.payload.build()[:64]
                eth_ip_header[Ether].src = incoming[Ether].dst

            if icmp:
                # failed. send ICMP unreachable.
                reply_packet = eth_ip_header / icmp
                self.transmit(incoming.src, reply_packet.build())
                return

            eth_ip_header[Ether].src = incoming[Ether].dst
            # okay now process UDP
            data = incoming[UDP].load
            val = None
            cmd = data.decode("ascii")
            if ' ' in cmd:
                cmd, val = cmd.split(' ', 1)
            response = "CMD NOT FOUND. BLYAT\n"
            if cmd:
                cmd = cmd.lower().strip()
                if cmd == "help":
                    response = BOATHELP
                elif cmd == "antenna":
                    response = self.antenna()
                elif cmd == "position":
                    response = self.position()
                elif cmd == "info":
                    response = self.info()
                elif cmd == "code":
                    response = self.code()
                elif cmd == "detonate":
                    response = self.detonate()

            reply_packet = eth_ip_header / UDP(sport=incoming[UDP].dport, dport=incoming[UDP].sport) / response
            self.transmit(incoming[Ether].src, reply_packet.build())

            if cmd == "detonate":
                # now clean up the bss from the list, as the boat is dead
                del self.bss.ap.bssids[self.bss.mac]

        elif TCP in incoming:
            # reject TCP
            eth_ip_header = Ether(src=self.bss.mac, dst=incoming[Ether].src) \
                    / IP(dst=incoming[IP].src, src=self.ip)
            icmp = ICMP(type=3, code=2) / incoming.payload.build()[:64]
            reply_packet = eth_ip_header / icmp
            self.transmit(incoming.src, reply_packet.build())
        else:
            printd("smtg else")
            printd(incoming.show(dump=1))


    def reply_dhcp_offer(self, incoming):
        # generate an IP
        if incoming.src not in self.macs:
            self.macs.append(incoming.src)
        dest_ip = "%s.%d" % (self.subnet, 1 + len(self.macs))

        deth = incoming.src
        smac = bytes.fromhex(deth.replace(':', ''))
        broadcast = "%s.255"%self.subnet
        gateway = server = self.ip
        netmask = "255.255.255.0"

        packet = Ether(dst='ff:ff:ff:ff:ff:ff', src=self.bss.mac, type=0x800) \
                 / IP(dst="255.255.255.255", src=self.ip) \
                 / UDP(sport=67, dport=68) \
                 / BOOTP(op=2, htype=1, yiaddr=dest_ip, siaddr=self.ip, chaddr=smac, xid=incoming[BOOTP].xid) \
                 / DHCP(options=[("message-type", "offer"), ("server_id", server), ("broadcast_address", broadcast), ("router", gateway), ("subnet_mask", netmask)])

        printd("send dhcp offer to " + deth)
        self.transmit(deth, packet.build())

    def reply_dhcp_ack(self, incoming):
        # generate an IP
        if incoming.src not in self.macs:
            self.macs.append(incoming.src)
        dest_ip = "%s.%d" % (self.subnet, 2 + self.macs.index(incoming.src))

        deth = incoming.src
        smac = bytes.fromhex(deth.replace(':', ''))
        broadcast = "%s.255"%self.subnet
        gateway = server = self.ip
        netmask = "255.255.255.0"

        packet = Ether(dst='ff:ff:ff:ff:ff:ff', src=self.bss.mac, type=0x800) \
                 / IP(dst="255.255.255.255", src=self.ip) \
                 / UDP(sport=67, dport=68) \
                 / BOOTP(op=2, htype=1, yiaddr=dest_ip, siaddr=self.ip, chaddr=smac, xid=incoming[BOOTP].xid) \
                 / DHCP(options=[("message-type", "ack"), ("server_id", server), ("broadcast_address", broadcast), ("lease_time", 1337), ("router", gateway), ("subnet_mask", netmask)])
        printd("send dhcp ack to " + deth)
        self.transmit(deth, packet.build())

    def run(self):
        self.data_ready.acquire()
        counter = 0
        while True:
            for incoming in self.txq:
                self.input(incoming)
            self.txq = []
            counter += 1
            self.data_ready.wait()
        self.data_ready.release()


class Station:
    def __init__(self, mac):
        self.mac = mac
        self.associated = False


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
    printd(hex(a))
    decrypt = pyaes.AESModeOfOperationECB(kek).decrypt
    for j in range(5, -1, -1):  #counting down
        for i in range(n, 0, -1):  #(n, n-1, ..., 1)
            ciphertext = struct.pack(">Q", a ^ (n * j + i)) + r[i]
            printd(len(ciphertext))
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

class BSS:
    def __init__(self, ap, ssid, mac, psk, ip="10.10.10.1/24" ):
        self.ap = ap
        self.ssid = ssid
        self.mac = mac
        self.PSK = psk
        self.ip =  ip
        self.sc = 0
        self.aid = 0
        self.stations = {}
        self.GTK = b""
        self.mutex = threading.Lock()
        self.network = Network(self, ip=ip)

    def next_sc(self):
        self.mutex.acquire()
        self.sc = (self.sc + 1) % 4096
        temp = self.sc
        self.mutex.release()

        return temp * 16  # Fragment number -> right 4 bits

    def next_aid(self):
        self.mutex.acquire()
        self.aid = (self.aid + 1) % 2008
        temp = self.aid
        self.mutex.release()
        return temp

    def gen_gtk(self):
        self.gtk_full = open("/dev/urandom", "rb").read(32)
        self.GTK = self.gtk_full[:16]
        self.MIC_AP_TO_GROUP = self.gtk_full[16:24]
        self.group_IV = count()

class AP:
    def __init__(self, ssid, psk, mac=None, mode="stdio", iface="wlan0"):
        self.iface = iface
        self.mode = mode
        if self.mode == "iface":
            mac = if_hwaddr(iface)
        if not mac:
          raise Exception("Need a mac")
        else:
          self.mac = mac
        self.channel = 1
        self.boottime = time()

        self.bssids = {mac: BSS(self, ssid, mac, psk, "10.10.0.1/24")}
        self.beaconTransmitter = self.BeaconTransmitter(self)

    def activate_next(self):
        # create a new BSS now
        mac = "02:00:00:00:00:00"
        ssid = boats[BOAT_IDX] # same as boat name
        psk = gen_psk(ssid)
        self.bssids[mac] = BSS(self, ssid, mac, psk, ip="10.10.%d.1/24"%BOAT_IDX)
        self.bssids[mac].network.start()
        printd("new BSS made %s" %ssid)

    def ssids(self):
        return [bss[x].ssid for x in self.bssids]

    def get_radiotap_header(self):
        return RadioTap()

    def get_ssid(self, mac):
        if mac not in self.bssids:
            return None
        return self.bssids[mac].ssid

    def current_timestamp(self):
        return int((time() - self.boottime) * 1000000)

    def tun_data_incoming(self, bss, sta, incoming):
        p = Ether(incoming)
        self.enc_send(bss, sta, p)

    def recv_pkt(self, packet):
        try:
            if len(packet.notdecoded[8:9]) > 0:  # Driver sent radiotap header flags
                # This means it doesn't drop packets with a bad FCS itself
                flags = ord(packet.notdecoded[8:9])
                if flags & 64 != 0:  # BAD_FCS flag is set
                    # Print a warning if we haven't already discovered this MAC
                    if not packet.addr2 is None:
                        printd(
                            "Dropping corrupt packet from %s" % packet.addr2,
                            Level.BLOAT,
                        )
                    # Drop this packet
                    return

            if EAPOL in packet:
                # send message 3
                self.create_eapol_3(packet)
            elif Dot11CCMP in packet:
                if packet[Dot11].FCfield == "to-DS+protected":
                    sta = packet[Dot11].addr2
                    bssid = packet[Dot11].addr1
                    if bssid not in self.bssids:
                        printd("[-] Invalid bssid destination for packet")
                        return
                    decrypted = self.decrypt(bssid, sta, packet)
                    if decrypted:
                        # make sure that the ethernet src matches the station,
                        # otherwise block
                        if sta != decrypted[Ether].src:
                            printd("[-] Invalid mac address for packet")
                            return
                        #self.tunnel.write(decrypted)
                        #printd("write to %s from %s" % (bssid, sta))
                        self.bssids[bssid].network.write(decrypted) #packet from a client
                    else:
                        printd("failed to decrypt %s to %s" % (sta, bssid))
                    return

            # Management
            if packet.type == DOT11_TYPE_MANAGEMENT:
                if packet.subtype == DOT11_SUBTYPE_PROBE_REQ:  # Probe request
                    if Dot11Elt in packet:
                        ssid = packet[Dot11Elt].info

                        printd(
                            "Probe request for SSID %s by MAC %s"
                            % (ssid, packet.addr2),
                            Level.DEBUG,
                        )

                        if Dot11Elt in packet and packet[Dot11Elt].len == 0:
                            # for empty return primary ssid
                            self.dot11_probe_resp(self.mac, packet.addr2, self.bssids[self.mac].ssid)
                        else:
                            # otherwise return match
                            for x in self.bssids:
                                # otherwise only respond to a match
                                if self.bssids[x].ssid == ssid:
                                    self.dot11_probe_resp(x, packet.addr2, ssid)
                                    break
                elif packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # Authentication
                    bssid = packet.addr1
                    if bssid in self.bssids:  # We are the receivers
                        self.bssids[bssid].sc = -1 # Reset sequence number
                        self.dot11_auth(bssid, packet.addr2)
                elif (
                    packet.subtype == DOT11_SUBTYPE_ASSOC_REQ
                    or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ
                ):
                    if packet.addr1 in self.bssids:
                        self.dot11_assoc_resp(packet, packet.addr2, packet.subtype)
        except SyntaxError as err:
            printd("Unknown error at monitor interface: %s" % repr(err))

    def dot11_probe_resp(self, bssid, source, ssid):
        printd("send probe response to " +  source)
        probe_response_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=5,
                addr1=source,
                addr2=bssid,
                addr3=bssid,
                SC=self.bssids[bssid].next_sc(),
            )
            / Dot11ProbeResp(
                timestamp=self.current_timestamp(), beacon_interval=0x0064, cap=0x3101
            )
            / Dot11Elt(ID="SSID", info=ssid)
            / Dot11Elt(ID="Rates", info=AP_RATES)
            / Dot11Elt(ID="DSset", info=chr(self.channel))
        )

        # If we are an RSN network, add RSN data to response
        probe_response_packet = probe_response_packet / RSN

        self.sendp(probe_response_packet, verbose=False)

    def dot11_auth(self, bssid, receiver):
        bss = self.bssids[bssid]
        auth_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=0x0B,
                addr1=receiver,
                addr2=bssid,
                addr3=bssid,
                SC=bss.next_sc(),
            )
            / Dot11Auth(seqnum=0x02)
        )

        printd("Sending Authentication  from %s to %s (0x0B)..." % (receiver, bssid), Level.DEBUG)
        self.sendp(auth_packet, verbose=False)

    def create_eapol_3(self, message_2):
        bssid = message_2.getlayer(Dot11).addr1
        sta = message_2.getlayer(Dot11).addr2

        printd("eapol 3 incoming " + sta + " " + bssid)
        if sta in self.bssids:
            return

        if bssid not in self.bssids:
            return

        bss = self.bssids[bssid]

        if sta not in bss.stations:
            printd("bss %s does not know station  %s" % (bss, sta))
            return

        if not bss.stations[sta].eapol_ready:
            printd("station %s not eapol ready" % sta)
            return

        eapol_key = EAPOL_KEY(message_2.getlayer(EAPOL).payload.load)

        snonce = eapol_key.key_nonce

        amac = bytes.fromhex(bssid.replace(":", ""))
        smac = bytes.fromhex(sta.replace(":", ""))

        stat = bss.stations[sta]
        stat.PMK = PMK = hashlib.pbkdf2_hmac(
            "sha1", bss.PSK.encode(), bss.ssid.encode(), 4096, 32
        )
        # UM do we need to sort here
        stat.PTK = PTK = customPRF512(PMK, amac, smac, stat.ANONCE, snonce)
        stat.KCK = PTK[:16]
        stat.KEK = PTK[16:32]
        stat.TK = PTK[32:48]
        stat.MIC_AP_TO_STA = PTK[48:56]
        stat.MIC_STA_TO_AP = PTK[56:64]
        stat.client_iv = count()

        #verify message 2 key mic matches before proceeding
        #verify MIC in packet makes sense
        in_eapol = message_2[EAPOL]
        ek = EAPOL_KEY(in_eapol.payload.load)
        given_mic = ek.key_mic
        to_check = in_eapol.build().replace(ek.key_mic, b"\x00"*len(ek.key_mic))
        computed_mic = hmac.new(stat.KCK, to_check, hashlib.sha1).digest()[:16]
        if given_mic != computed_mic:
            printd("[-] Invalid MIC from STA. Dropping EAPOL key exchange message and station")
            printd("my bssid " + bssid)
            printd('my psk ' + bss.PSK)
            printd('amac ' + bssid)
            printd('smac ' + sta)
            import binascii
            printd(b'KCK ' + binascii.hexlify(stat.KCK))
            printd(b'PMK' + binascii.hexlify(stat.PMK))
            printd(b'TK' + binascii.hexlify(stat.PTK))
            printd(b'given mic' + binascii.hexlify(given_mic))
            printd(b'computed mic' + binascii.hexlify(computed_mic))
            deauth =    self.get_radiotap_header() \
                        / Dot11(
                            addr1=sta,
                            addr2=bssid,
                            addr3=bssid
                        ) \
                        / Dot11Deauth(reason=1)
            #self.sendp(deauth, verbose=False)
            #del bss.stations[sta]
            # relax auth failure
            return

        bss.stations[sta].eapol_ready = False

        if bss.GTK == b"":
            bss.gen_gtk()

        stat.KEY_IV = bytes([0 for i in range(16)])

        gtk_kde = b"".join(
            [
                chb(0xDD),
                chb(len(bss.GTK) + 6),
                b"\x00\x0f\xac",
                b"\x01\x00\x00",
                bss.GTK,
                b"\xdd\x00",
            ]
        )
        plain = pad_key_data(RSN + gtk_kde)
        keydata = aes_wrap(stat.KEK, plain)

        ek = EAPOL(version="802.1X-2004", type="EAPOL-Key") / EAPOL_KEY(
            key_descriptor_type=2,
            key_descriptor_type_version=2,
            install=1,
            key_type=1,
            key_ack=1,
            has_key_mic=1,
            secure=1,
            encrypted_key_data=1,
            key_replay_counter=2,
            key_nonce=stat.ANONCE,
            key_mic=(b"\x00" * 16),
            key_length=16,
            key=keydata,
            wpa_key_length=len(keydata),
        )

        ek.key_mic = hmac.new(stat.KCK, ek.build(), hashlib.sha1).digest()[:16]

        m3_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=0,
                FCfield="from-DS",
                addr1=sta,
                addr2=bssid,
                addr3=bssid,
                SC=bss.next_sc(),
            )
            / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0, code=0x888E)
            / ek
        )

        self.sendp(m3_packet, verbose=False)
        stat.associated = True
        printd("[+] New associated station %s for bssid %s" % (sta, bssid))

        bss.stations[sta] = stat

    def create_message_1(self, bssid, sta):
        if sta in self.bssids:
            return

        if bssid not in self.bssids:
            return

        bss = self.bssids[bssid]

        if sta not in bss.stations:
            return

        stat = bss.stations[sta]
        stat.ANONCE = anonce = bytes([random.randrange(256) for i in range(32)])
        m1_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=0,
                FCfield="from-DS",
                addr1=sta,
                addr2=bssid,
                addr3=bssid,
                SC=bss.next_sc(),
            )
            / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0, code=0x888E)
            / EAPOL(version="802.1X-2004", type="EAPOL-Key")
            / EAPOL_KEY(
                key_descriptor_type=2,
                key_descriptor_type_version=2,
                key_type=1,
                key_ack=1,
                has_key_mic=0,
                key_replay_counter=1,
                key_nonce=anonce,
                key_length=16,
            )
        )
        stat.eapol_ready = True
        printd("sent eapol m1 " + sta)
        self.sendp(m1_packet, verbose=False)
        bss.stations[sta] = stat

    def dot11_assoc_resp(self, packet, sta, reassoc):
        bssid = packet.addr1
        bss = self.bssids[bssid]
        if sta not in bss.stations:
            bss.stations[sta] = Station(sta)

        response_subtype = 0x01
        if reassoc == 0x02:
            response_subtype = 0x03
        self.eapol_ready = True
        assoc_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=response_subtype,
                addr1=sta,
                addr2=bssid,
                addr3=bssid,
                SC=bss.next_sc(),
            )
            / Dot11AssoResp(cap=0x3101, status=0, AID=bss.next_aid())
            / Dot11Elt(ID="Rates", info=AP_RATES)
        )

        printd("Sending Association Response (0x01)...")
        self.sendp(assoc_packet, verbose=False)
        self.create_message_1(bssid, sta)

    def decrypt(self, bssid, sta, packet):
        if bssid not in self.bssids:
            return
        bss = self.bssids[bssid]
        ccmp = packet[Dot11CCMP]
        pn = ccmp_pn(ccmp)
        if sta not in bss.stations:
            printd("[-] Unknown station %s" % sta)
            deauth =    self.get_radiotap_header() \
                        / Dot11(
                            addr1=sta,
                            addr2=bssid,
                            addr3=bssid
                        ) \
                        / Dot11Deauth(reason=9)
            self.sendp(deauth, verbose=False)
            return None
        station = bss.stations[sta]
        return self.decrypt_ccmp(packet, station.TK, bss.GTK)

    def encrypt(self, bss, sta, packet, key_idx):
        key = ""
        if key_idx == 0:
            pn = next(bss.stations[sta].client_iv)
            key = bss.stations[sta].TK
        else:
            pn = next(bss.group_IV)
            key = bss.GTK
        return self.encrypt_ccmp(bss, sta, packet, key, pn, key_idx)

    def enc_send(self, bss, sta, packet):
        key_idx = 0
        if is_multicast(sta) or is_broadcast(sta):
            printd('sending broadcast/multicast')
            key_idx = 1
        elif sta not in bss.stations or not bss.stations[sta].associated:
            printd("[-] Invalid station %s" % sta)
            return
        x = self.get_radiotap_header()
        y = self.encrypt(bss, sta, packet, key_idx)
        if not y:
            raise Exception("wtfbbq")
        new_packet = x / y
        #printd(new_packet.show(dump=1))
        self.sendp(new_packet, verbose=False)

    def encrypt_ccmp(self, bss, sta, p, tk, pn, keyid=0, amsdu_spp=False):
        # Takes a plaintext ethernet frame and encrypt and wrap it into a Dot11/DotCCMP
        # Add the CCMP header. res0 and res1 are by default set to zero.
        SA = p[Ether].src
        DA = p[Ether].dst
        newp = Dot11(
            type="Data",
            FCfield="from-DS+protected",
            addr1=sta,
            addr2=bss.mac,
            addr3=SA,
            SC=bss.next_sc(),
        )
        newp = newp / Dot11CCMP()

        pn_bytes = pn2bytes(pn)
        newp.PN0, newp.PN1, newp.PN2, newp.PN3, newp.PN4, newp.PN5 = pn_bytes
        newp.key_id = keyid
        newp.ext_iv = 1
        priority = 0  # ...
        ccm_nonce = ccmp_get_nonce(priority, newp.addr2, pn)
        ccm_aad = ccmp_get_aad(newp, amsdu_spp)
        header = LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=p[Ether].type)
        payload = (header / p.payload).build()
        ciphertext, tag = CCMPCrypto.run_ccmp_encrypt(tk, ccm_nonce, ccm_aad, payload)
        newp.data = ciphertext + tag
        return newp

    def decrypt_ccmp(self, p, tk, gtk, verify=True, dir='to_ap'):
        # Takes a Dot11CCMP frame and decrypts it
        keyid = p.key_id
        if keyid == 0:
            pass
        elif keyid == 1:
            tk = gtk
        else:
            raise Exception("unknown key id", key_id)

        priority = dot11_get_priority(p)
        pn = dot11_get_iv(p)

        ccm_nonce = ccmp_get_nonce(priority, p.addr2, pn)
        ccm_aad = ccmp_get_aad(p[Dot11])

        payload = p[Dot11CCMP].data
        tag = payload[-8:]
        payload = payload[:-8]
        plaintext, valid = CCMPCrypto.run_ccmp_decrypt(
            tk, ccm_nonce, ccm_aad, payload, tag
        )
        if verify and not valid:
            printd("[-] ERROR on ccmp decrypt, invalid tag")
            return None
        llc = LLC(plaintext)
        # convert into an ethernet packet.
        # decrypting TO-AP. addr3/addr2.  if doing FROM-AP need to do addr1/addr3
        DA = p.addr3
        SA = p.addr2
        if dir == 'from_ap':
            DA = p.addr1
            SA = p.addr3
        return Ether(
            addr2bin(DA)
            + addr2bin(SA)
            + struct.pack(">H", llc.payload.code)
            + llc.payload.payload.build()
        )

    def dot11_beacon(self, bssid, ssid):
        # Create beacon packet
        beacon_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid
            )
            / Dot11Beacon(cap=0x3101)
            / Dot11Elt(ID="SSID", info=ssid)
            / Dot11Elt(ID="Rates", info=AP_RATES)
            / Dot11Elt(ID="DSset", info=chr(self.channel))
        )

        beacon_packet = beacon_packet / RSN

        # Update timestamp
        beacon_packet[Dot11Beacon].timestamp = self.current_timestamp()

        # Send
        self.sendp(beacon_packet, verbose=False)

    class BeaconTransmitter(threading.Thread):
        def __init__(self, ap):
            threading.Thread.__init__(self)
            self.ap = ap
            self.daemon = True
            self.interval = 0.1

        def run(self):
            counter = 0
            while True:
                counter += 1
                # occassionally, we should send a EAPOL msg 2
                # that could be cracked with the password.
                for bssid in self.ap.bssids.keys():
                    bss = self.ap.bssids[bssid]
                    self.ap.dot11_beacon(bss.mac, bss.ssid)

                if counter % 10 == 0:
                    # send UDP status message to every client
                    for bssid in self.ap.bssids.keys():
                        bss = self.ap.bssids[bssid]
                        for sta in bss.stations.keys():
                            #pick a bunk IP address
                            ip = IP(src=bss.network.ip, dst="192.168.1.2")
                            udp = UDP(sport=random.randrange(0,65536), dport=2422)
                            p = Ether(dst=sta, src=bss.mac) / ip / udp / "info\n"
                            # transmit this
                            self.ap.enc_send(bss, sta, p)
                # Sleep
                sleep(self.interval)

    def run(self):
        self.beaconTransmitter.start()
        for x in self.bssids:
            self.bssids[x].network.start()
        #tbd need to read from stdin
        if self.mode == "iface":
            sniff(iface=self.iface, prn=self.recv_pkt, store=0, filter='')
            return
        assert self.mode == "stdio"
        os.set_blocking(sys.stdin.fileno(), False)
        qdata = b""
        while True:
          sleep(0.01)
          data = sys.stdin.buffer.read(65536)
          if data:
              qdata += data
          if len(qdata) > 4:
              wanted = struct.unpack("<L", qdata[:4])[0]
              if len(qdata) + 4 >= wanted:
                  p = RadioTap(qdata[4:4 + wanted])
                  self.recv_pkt(p)
                  qdata = qdata[4 + wanted:]

    def sendp(self, packet, verbose=False):
        if self.mode == "stdio":
            x = packet.build()
            sys.stdout.buffer.write(struct.pack("<L", len(x)) + x)
            sys.stdout.buffer.flush()
            return
        assert self.mode == "iface"
        sendp(packet, iface=self.iface, verbose=False)

if __name__ == "__main__":
    #ap = AP("turtlenet", "password1234", mac="44:44:44:00:00:00", mode="iface", iface="mon0")
    ap = AP("defcon2023", "defcon2023", mac="02:00:00:00:00:00", mode="stdio")
    ap.run()
