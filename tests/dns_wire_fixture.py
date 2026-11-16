# DNS fixture extracted from dns-lexicon commit 60afe5db.
# Source SHA256: 642c84877f4bd8acd9e15878978d8f2434450f650d9ff8c31f3e382958967b48
# Socket metadata added for dnspython 2.7 compatibility.

import base64

import io

import socket

import struct

import dns.exception

import dns.flags

import dns.message

import dns.name

import dns.opcode

import dns.rcode

import dns.rdataclass

import dns.rdatatype

import dns.rrset

import dns.tsig

import dns.zone

TOKEN = "hmac-sha512:test-key:" + base64.b64encode(b"public-test-secret").decode()

ZONE = """
@ 300 IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 300
@ 300 IN NS ns.example.com.
ns 300 IN A 192.0.2.53
"""


class DNSServer:
    """Minimal authoritative fixture: signed AXFR and RFC 2136 add/delete."""

    def __init__(self):
        self.server_address = ("127.0.0.1", 5353)
        self.zone = dns.zone.from_text(ZONE, origin="example.com.", relativize=False)
        self.key = dns.tsig.Key("test-key", b"public-test-secret", "hmac-sha512")
        self.keyring = {self.key.name: self.key}
        self.rcode = dns.rcode.NOERROR
        self.truncate = False
        self.unsigned = False
        self.corrupt = False
        self.messages = 0
        self.writes = 0
        self.before_update = None
        self.update_rcode = dns.rcode.NOERROR
        self.update_rcodes = {}
        self.lost_reply_updates = set()
        self.axfr_zone = None
        self.transfers = 0
        self.axfr_batch_size = 1
        self.update_unsigned = False
        self.update_corrupt = False

    def changed(self):
        """Publish a new SOA serial after a fixture zone change."""
        soa = self.zone.find_rdataset(self.zone.origin, "SOA")
        data = next(iter(soa))
        soa.clear()
        soa.add(data.replace(serial=data.serial + 1))


class DNSHandler:
    """Use actual DNS wire messages, including chained TSIG transfer signatures."""

    def __init__(self, server, wire):
        self.server = server
        self.rfile = io.BytesIO(wire)
        self.wfile = io.BytesIO()

    def handle(self):
        server = self.server
        length = struct.unpack("!H", self.rfile.read(2))[0]
        query = dns.message.from_wire(self.rfile.read(length), keyring=server.keyring)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if query.question[0].name != server.zone.origin:
            response.set_rcode(dns.rcode.NOTAUTH)
        else:
            response.set_rcode(server.rcode)
        if response.rcode() != dns.rcode.NOERROR:
            self.send(response)
        elif query.opcode() == dns.opcode.UPDATE:
            server.writes += 1
            response.set_rcode(
                server.update_rcodes.get(server.writes, server.update_rcode)
            )
            if response.rcode() != dns.rcode.NOERROR:
                self.send(response)
                return
            if server.before_update:
                callback, server.before_update = server.before_update, None
                callback()
            response.set_rcode(self.check_prerequisites(query))
            if response.rcode() != dns.rcode.NOERROR:
                self.send(response)
                return
            for rrset in query.authority:
                owner = rrset.name.derelativize(server.zone.origin)
                if rrset.deleting == dns.rdataclass.ANY:
                    node = server.zone.get_node(owner)
                    if node:
                        for dataset in list(node.rdatasets):
                            if rrset.rdtype not in (dns.rdatatype.ANY, dataset.rdtype):
                                continue
                            if owner == server.zone.origin and dataset.rdtype in (
                                dns.rdatatype.SOA,
                                dns.rdatatype.NS,
                            ):
                                continue
                            server.zone.delete_rdataset(owner, dataset.rdtype)
                elif rrset.deleting == dns.rdataclass.NONE:
                    rdataset = server.zone.get_rdataset(owner, rrset.rdtype)
                    if rdataset is not None:
                        for data in rrset:
                            if owner == server.zone.origin and (
                                rrset.rdtype == dns.rdatatype.SOA
                                or (
                                    rrset.rdtype == dns.rdatatype.NS
                                    and len(rdataset) == 1
                                )
                            ):
                                continue
                            rdataset.discard(data)
                        if not rdataset:
                            server.zone.delete_rdataset(owner, rrset.rdtype)
                else:
                    if rrset.rdtype == dns.rdatatype.SOA:
                        current = server.zone.get_rdataset(owner, "SOA")
                        if current is None:
                            continue
                        delta = (
                            next(iter(rrset)).serial - next(iter(current)).serial
                        ) % 2**32
                        if not 0 < delta < 2**31:
                            continue
                    node = server.zone.get_node(owner)
                    if node and any(
                        (rrset.rdtype == dns.rdatatype.CNAME)
                        != (dataset.rdtype == dns.rdatatype.CNAME)
                        for dataset in node.rdatasets
                    ):
                        # RFC 2136 3.4.2.2: silently ignore conflicting adds.
                        continue
                    rdataset = server.zone.find_rdataset(
                        owner, rrset.rdtype, create=True
                    )
                    for data in rrset:
                        rdataset.add(data)
                    rdataset.ttl = rrset.ttl
            server.changed()
            if server.writes in server.lost_reply_updates:
                raise dns.exception.Timeout()
            self.send(response)
        else:
            server.transfers += 1
            zone = server.axfr_zone if server.axfr_zone is not None else server.zone
            soa = zone.find_rrset(zone.origin, "SOA")
            rrsets = [soa]
            rrsets.extend(
                zone.find_rrset(owner, rdataset.rdtype)
                for owner, rdataset in zone.iterate_rdatasets()
                if rdataset.rdtype != dns.rdatatype.SOA
            )
            if not server.truncate:
                rrsets.append(soa)
            context = None
            # Tests default to one RRset per message. Benchmarks can model
            # authorities that pack several RRsets into each TCP message.
            for start in range(0, len(rrsets), server.axfr_batch_size):
                response = dns.message.make_response(query)
                response.flags |= dns.flags.AA
                response.answer.extend(rrsets[start : start + server.axfr_batch_size])
                context = self.send(response, multi=True, context=context)

    def check_prerequisites(self, query):
        """Evaluate name/RRset existence and exact RDATA sets before any writes."""
        values = {}
        for rrset in query.prerequisite:
            owner = rrset.name.derelativize(self.server.zone.origin)
            node = self.server.zone.get_node(owner)
            dataset = self.server.zone.get_rdataset(owner, rrset.rdtype)
            exists = (
                bool(node and node.rdatasets)
                if rrset.rdtype == dns.rdatatype.ANY
                else bool(dataset)
            )
            if rrset.deleting == dns.rdataclass.NONE:
                if exists:
                    return (
                        dns.rcode.YXDOMAIN
                        if rrset.rdtype == dns.rdatatype.ANY
                        else dns.rcode.YXRRSET
                    )
            elif rrset.deleting == dns.rdataclass.ANY:
                if not exists:
                    return (
                        dns.rcode.NXDOMAIN
                        if rrset.rdtype == dns.rdatatype.ANY
                        else dns.rcode.NXRRSET
                    )
            else:
                values.setdefault((owner, rrset.rdtype), set()).update(rrset)
        for (owner, rtype), wanted in values.items():
            if set(self.server.zone.get_rdataset(owner, rtype) or ()) != wanted:
                return dns.rcode.NXRRSET
        return dns.rcode.NOERROR

    def send(self, response, multi=False, context=None):
        server = self.server
        if server.unsigned or (
            response.opcode() == dns.opcode.UPDATE and server.update_unsigned
        ):
            response.tsig = None
        wire = response.to_wire(multi=multi, tsig_ctx=context)
        if server.corrupt or (
            response.opcode() == dns.opcode.UPDATE and server.update_corrupt
        ):
            wire = wire[:-1] + bytes([wire[-1] ^ 1])
        server.messages += 1
        self.wfile.write(struct.pack("!H", len(wire)) + wire)
        self.wfile.flush()
        return response.tsig_ctx


class MemorySocket:
    """Only the transport is substituted; dnspython encodes and validates DNS.

    Fragment reads to exercise DNS TCP framing as well as multi-message AXFR.
    No query, transfer, signature validation or provider method is mocked.
    """

    def __init__(self, server, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
        self.server = server
        self.family = family
        self.type = type
        self.proto = proto
        assert type == socket.SOCK_STREAM, "This fixture implements DNS over TCP only"
        self.pending = bytearray()
        self.replies = io.BytesIO()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def setblocking(self, _):
        pass

    def connect_ex(self, _):
        return 0

    def send(self, data):
        self.pending.extend(data)
        if len(self.pending) >= 2:
            length = struct.unpack("!H", self.pending[:2])[0]
            if len(self.pending) == length + 2:
                handler = DNSHandler(self.server, self.pending)
                handler.handle()
                self.replies = io.BytesIO(handler.wfile.getvalue())
        return len(data)

    def recv(self, count):
        return self.replies.read(min(count, 71))
