# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

import re
import socket
from cpython.array cimport array
from libc.stdint cimport uint16_t, uint32_t
cimport cython

from packets.core.inetpkt cimport PKT, set_bit, unset_bit, \
    set_short_nibble, get_short_nibble, rd_u16, rd_u32, rd_bytes, \
    need_bytes, PktWriter, w_u8, w_u16, w_u32, w_bytes, w_set_u16, _serialize

# Regex to see if data is a valid domain name
hostname_re = re.compile("^(?:(?!-|[^.]+_)[A-Za-z0-9-_]{1,63}(?<!-)"
                         "(?:\.|$))$")
domainname_re = re.compile("^(?=.{1,253}\.?$)(?:(?!-|[^.]+_)[A-Za-z0-9-_]"
                           "{1,63}(?<!-)(?:\.|$)){2,}$")

email_re = re.compile("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")


cdef array hostname_to_label_array(bytes hostname):
    """ Convert a hostname or FQDN to DNS label notation. For example:
        www.riverbed.com becomes [3,119,119,119,8,114,...,100,3,99,111,109,0]
        Args:
            :hostname (bytes): A "dot notation" host name as defined in RFC 
                1123

        Returns: 
            :bytes: DNS label notation list as shown in TCP/IP Illustrated 
                Chapter 14 or RFC 1035
    """
    cdef:
        array out
        bytes part, ch

    if domainname_re.match(hostname) or hostname_re.match(hostname):
        out = array('B')
        for part in hostname.split('.'):
            out.append(len(part))
            for ch in part:
                out.append(ord(ch))
        out.append(0)
        return out
    else:
        raise ValueError("hostname_to_label_array(hostname): hostname "
                         "argument must be valid RFC 1123 FQDN. Argument "
                         "was: {0}".format(hostname))

cdef int w_dns_name(PktWriter w,
                    str dns_name,
                    Py_ssize_t dns_start,
                    dict labels,
                    bint compress=1) except -1:
    """ Used to write DNS name into packet data. See read_dns_name_bytes for 
        a description of the name formats.

        Labels are written straight into the shared output buffer rather than
        collected as a list of bytes objects and joined. There is no separate
        offset counter either: RFC 1035 compression pointers are relative to
        the start of the DNS message, so the offset a label must be recorded
        at is simply how far into the message the writer already is.

        Args:
            :w (PktWriter): the output buffer to append to.
            :dns_name (str): dns name for this record.
            :dns_start (Py_ssize_t): position in w where this DNS message
                begins. Compression offsets are measured from here.
            :labels (dict): A per packet store of previously written labels 
                with their offsets in the packet data.
            :compress (bint): Should compression be used if possible. Default
                is 1 for yes

        Returns: 
            :int: 0, or -1 with an exception set.
    """
    cdef:
        list parts
        str suffix
        bytes label_bytes
        Py_ssize_t i, count, pos

    if dns_name == '':
        # Root / empty name: a single zero length label.
        return w_u8(w, 0)

    parts = dns_name.split('.')
    # Tolerate a fully qualified name written with a trailing dot.
    if parts and parts[-1] == '':
        parts.pop()

    count = len(parts)
    if compress:
        if dns_name.endswith('.'):
            suffix = dns_name[:-1]
        else:
            suffix = dns_name
    for i in range(count):
        # Each suffix of the name is a compression candidate. If the whole
        # remaining suffix was already written we emit a 2 byte pointer to it
        # and we are done. Building the candidate is only worth anything when
        # compression is on -- it used to be joined unconditionally, which is
        # why writing an uncompressed message measured slower than writing a
        # compressed one despite doing strictly less protocol work.
        if compress:
            if suffix in labels:
                return w_u16(w, <uint16_t>(LABEL + <Py_ssize_t>labels[suffix]))
            # Only offsets that fit in the 14 bit pointer field are reusable.
            pos = w.n - dns_start
            if pos < 0x4000:
                labels[suffix] = pos
        label_bytes = parts[i].encode()
        w_u8(w, <unsigned char>len(label_bytes))
        w_bytes(w, label_bytes)
        if compress and i + 1 < count:
            suffix = suffix[len(parts[i]) + 1:]
    # No suffix matched: terminate the name with the root label.
    return w_u8(w, 0)

cdef str read_dns_name_bytes(const unsigned char[:] byte_array,
                             uint16_t* offset,
                             dict label_store):
    """ Used to read DNS name labels out of DNS packets. These labels can be in
        two formats. Uncompressed as '3www8riverbed3com0'. This would have a
        decimal representation of:
            [3,119,119,119,8,114,105,...,101,100,3,99,111,109,0]
        or in the packet data as:
            '\x03www\x08ri...ed\x03com\x00'
        The second format is compressed. With compressed data some part of the
        name has previously been seen. In that case the name will be as a 16bit
        value where the 2 most significant bits are set to '11' and the
        remaining 14 bits specify the number of bytes into the packet where the
        name can be found. So if 'www.riverbed.com' the first query in a DNS
        packet then it would have been seen at byte 12. So a later reference to
        it would look like '\xc0\x0c' or 49164 in decimal.

        Args:
            :byte_array (const unsigned char[:]): packet data as a typed
                memoryview over the packet buffer.
            :offset (uint16_t*): pointer to location in the packet where this 
                name starts
            :label_store (dict): A per packet mapping from label offsets to
                resolved suffix strings.

        Returns: 
            :str: human readable name.
    """
    cdef:
        uint16_t location, label_offset, pointer_offset
        Py_ssize_t index
        str c_label, suffix
        unsigned char b1
        bint have_pointer
        list label_offsets, parts

    have_pointer = 0
    pointer_offset = 0
    suffix = ''
    label_offsets = list()
    parts = list()

    while True:
        need_bytes(byte_array, offset[PNTR] + 1, 'DNS')
        label_offset = offset[PNTR]
        b1 = byte_array[offset[PNTR]]
        if 1 <= b1 <= 63:
            need_bytes(byte_array, offset[PNTR] + 1 + b1, 'DNS')
            c_label = rd_bytes(byte_array,
                                offset[PNTR] + 1,
                                offset[PNTR] + 1 + b1).decode()
            label_offsets.append(label_offset)
            parts.append(c_label)
            offset[PNTR] += b1 + 1
        elif b1 == 0:
            label_store[label_offset] = ''
            offset[PNTR] += 1
            break
        elif b1 & 0xc0 == 0xc0:
            need_bytes(byte_array, offset[PNTR] + 2, 'DNS')
            pointer_offset = offset[PNTR]
            location = rd_u16(byte_array, offset[PNTR])
            offset[PNTR] += 2
            location = location & 0x3fff
            if location in label_store:
                suffix = label_store[location]
                have_pointer = 1
            else:
                raise ValueError("read_dns_name_bytes encountered unexpected "
                                 "compressed data in byte_array. Array bytes "
                                 "are: {0}"
                                 "".format(
                    rd_bytes(byte_array, offset[PNTR] - 2, -1))
                )
            break
        else:
            raise ValueError("read_dns_name_bytes encountered invalid label "
                             "length {0}".format(b1))

    if have_pointer:
        # A later pointer may legally target this pointer rather than the
        # original labels, so pointer chains need their own offset entry.
        label_store[pointer_offset] = suffix
    for index in range(len(parts) - 1, -1, -1):
        if suffix:
            suffix = parts[index] + '.' + suffix
        else:
            suffix = parts[index]
        label_store[label_offsets[index]] = suffix
    return suffix


cdef tuple parse_resource(const unsigned char[:] byte_array,
                          uint16_t* offset,
                          dict label_store):
    """ Used to parse the initialization values for a DNSResource object from
        an array of bytes. 

        Args:
            :byte_array (const unsigned char[:]): packet data as a typed
                memoryview over the packet buffer.
            :offset (uint16_t*): pointer to location in the packet where this 
                DNSResource starts
            :label_store (dict): A per packet store of previously seen labels 
                with their offsets in the packet data. Used to call
                read_dns_name_bytes() or parse_soa()

        Returns: 
            :tuple: arguments that make up *this DNSResource object
    """
    cdef:
        uint16_t r_type, r_class, r_d_len
        uint32_t r_ttl
        str d_name, r_data

    d_name = read_dns_name_bytes(byte_array, offset, label_store)
    need_bytes(byte_array, offset[PNTR] + 10, 'DNS')
    r_type = rd_u16(byte_array, offset[PNTR])
    r_class = rd_u16(byte_array, offset[PNTR] + 2)
    r_ttl = rd_u32(byte_array, offset[PNTR] + 4)
    r_d_len = rd_u16(byte_array, offset[PNTR] + 8)
    offset[PNTR] += 10
    if r_type in (DNSTYPE_NS, DNSTYPE_CNAME, DNSTYPE_PTR):
        r_data = read_dns_name_bytes(byte_array,
                                     offset,
                                     label_store)
    elif r_type == DNSTYPE_A:
        r_data = socket.inet_ntop(socket.AF_INET,
                                  rd_bytes(byte_array, offset[PNTR],
                                           offset[PNTR] + 4))
        offset[PNTR] += 4
    elif r_type == DNSTYPE_AAAA:
        r_data = socket.inet_ntop(socket.AF_INET6,
                                  rd_bytes(byte_array, offset[PNTR],
                                           offset[PNTR] + 16))
        offset[PNTR] += 16
    elif r_type == DNSTYPE_SOA:
        r_data = parse_soa(byte_array, offset, &r_d_len, label_store)
    else:
        r_data = rd_bytes(byte_array, offset[PNTR],
                          offset[PNTR] + r_d_len).decode()
        offset[PNTR] += r_d_len
    return d_name, r_type, r_class, r_ttl, r_d_len, r_data


cdef str parse_soa(const unsigned char[:] data, uint16_t* offset,
                   uint16_t* rlen, dict label_store):
    """Used to parse the human readable value for a SOA type 
       DNSResource.res_data string from an array of bytes. 

        Args:
            :data (const unsigned char[:]): packet data as a typed
                memoryview over the packet buffer.
            :offset (uint16_t*): pointer to location in the packet where this 
                DNSResource starts
            :rlen (uint16_t*): pointer a uint16_t with the length in bytes of
                this SOA records resource data. Used to check from the
                unexpected case where a user directly feeds a parsed SOA to
                parse_soa() 
            :label_store (dict): A per packet store of previously seen labels 
                with their offsets in the packet data. Used to call
                read_dns_name_bytes() or parse_soa()

        Returns: 
            :bytes: human readable representation of SOA record.
    """
    cdef:
        uint16_t count, original_offset, index
        str mname, rname
        uint32_t serial, refresh, retry, expire, minimum

    original_offset = offset[PNTR]
    count = rd_bytes(data, offset[PNTR],
                     offset[PNTR] + rlen[PNTR]).count(b' ')

    if (count <= 7 and
            data.shape[0] - offset[PNTR] >= rlen[PNTR]):
        # its in binary format
        mname = read_dns_name_bytes(data, offset, label_store)
        rname = read_dns_name_bytes(data, offset, label_store)
        rname = rname.replace('.', '@', 1)
        need_bytes(data, offset[PNTR] + 20, 'DNS')
        serial = rd_u32(data, offset[PNTR])
        refresh = rd_u32(data, offset[PNTR] + 4)
        retry = rd_u32(data, offset[PNTR] + 8)
        expire = rd_u32(data, offset[PNTR] + 12)
        minimum = rd_u32(data, offset[PNTR] + 16)
        offset[PNTR] += 20
        return ('SOA mname: {0}, rname: {1}, serial: {2}, refresh: {3}, '
                'retry: {4}, expire: {5}, minimum: {6}'.format(
            mname, rname, serial, refresh, retry, expire, minimum))
    elif count == 15:
        # its already in printable format and being manually added. No need to
        # alter the offset values.
        return rd_bytes(data, 0, -1).decode()
    else:
        raise ValueError('parse_soa called on invalid soa data. Count was:{0}'
                         ', Data was: {1}'.format(
                             count, rd_bytes(data, 0, -1).decode()))


cdef int w_soa(PktWriter w, str res_data, Py_ssize_t dns_start, dict labels,
               bint compress=1) except -1:
    """ Function that writes the parts of a human readable SOA record (as
        created by parse_soa()) into the shared output buffer.
        Args:
            :w (PktWriter): the output buffer to append to.
            :res_data (str): The human readable form of SOA record.
            :dns_start (Py_ssize_t): position in w where this DNS message
                begins. Compression offsets are measured from here.
            :labels (dict): All the name labels in this packet as a dictionary.
            :compress (bint): Boolean governing compression
        Returns:
            :int: 0, or -1 with an exception set.
    """
    cdef:
        list parts

    parts = res_data.split()
    if len(parts) == 15:
        w_dns_name(w, parts[SOA_MNAME][:-1], dns_start, labels, compress)
        parts[SOA_RNAME] = parts[SOA_RNAME].replace('@', '.')
        w_dns_name(w, parts[SOA_RNAME][:-1], dns_start, labels, compress)
        w_u32(w, <uint32_t>int(parts[SOA_SER][:-1]))
        w_u32(w, <uint32_t>int(parts[SOA_REF][:-1]))
        w_u32(w, <uint32_t>int(parts[SOA_RET][:-1]))
        w_u32(w, <uint32_t>int(parts[SOA_EXP][:-1]))
        w_u32(w, <uint32_t>int(parts[SOA_MIN]))
        return 0
    else:
        raise ValueError('w_soa called on invalid soa data. '
                         'Data was: {0}'.format(res_data))

@cython.final
cdef class DNSQuery:

    def __init__(self,
                 str query_name,
                 uint16_t query_type,
                 uint16_t query_class):
        """ Simple class to wrap DNS queries
            Args:
                :query_name (bytes): The name for this query
                :query_type (uint16_t): query type. See DNSTYPE_ enums defined
                    in dns.pxd
                :query_class (uint16_t): query class. See RCLASS_ enums defined
                    in dns.pxd
        """

        self.query_type = query_type
        self.query_class = query_class
        self.query_name = query_name

    def __repr__(self):
        return ("DNSQuery(query_name={0}, query_type={1}, query_class={2})"
                "".format(self._query_name, self.query_type,
                          self.query_class))

    @property
    def query_name(self):
        return self._query_name

    @query_name.setter
    def query_name(self, str val):
        if (domainname_re.match(val) or
                hostname_re.match(val) or
                val == '' or
                self.query_type in (DNSTYPE_TXT,
                                    DNSTYPE_OPT)):
            self._query_name = val
        else:
            raise ValueError(
                "DNSQuery.query_name must be either a valid host name. "
                "Value was {0}".format(val))

    cdef int _write(self, PktWriter w, Py_ssize_t dns_start, dict labels,
                    bint compress=1) except -1:
        """Append this query to the shared output buffer. See w_dns_name for
        what dns_start is for."""
        w_dns_name(w, self._query_name, dns_start, labels, compress)
        w_u16(w, self.query_type)
        w_u16(w, self.query_class)
        return 0


@cython.final
cdef class DNSResource:
    """ Wrapper class for DNS resource record data. Includes some special
        handling for IPv4 and IPv6 record types, SOA records, and common DNS
        name record types like CNAME and PTR
        Args:
            :domain_name (bytes): string human readable dot notation fqdn for
                this resource. www.riverbed.com or 1.in-addr.arpa
            :res_type (uint16_t): type of resource A, CNAME, PTR, AAAA
            :res_class (uint16_t): Class of resource. Almost always 1 for inet.
            :res_ttl (uint32_t): How long this resource can live in seconds.
            :res_len (uint16_t): Length in bytes of res_data
            :res_data (bytes): Data for this resource as specified by type,
                class, and len
    """

    def __init__(self,
                 str domain_name,
                 uint16_t res_type,
                 uint16_t res_class,
                 uint32_t res_ttl,
                 uint16_t res_len,
                 str res_data):
        self.res_type = res_type
        self.res_class = res_class
        self.res_ttl = res_ttl
        self.res_len = res_len
        self.domain_name = domain_name
        self.res_data = res_data

    def __repr__(self):
        return ("DNSResource(domain_name={0}, res_type={1}, res_class={2}, "
                "res_ttl={3}, res_len={4}, res_data={5})"
                "".format(self._domain_name,
                          self.res_type,
                          self.res_class,
                          self.res_ttl,
                          self.res_len,
                          self.res_data))

    property domain_name:
        def __get__(self):
            return self._domain_name

        def __set__(self, str val):
            if (domainname_re.match(val) or
                    hostname_re.match(val) or
                    val == '' or
                    self.res_type in (DNSTYPE_TXT,
                                      DNSTYPE_OPT)):
                self._domain_name = val
            else:
                raise ValueError(
                    "DNSResource.domain_name must be either a valid host "
                    "name. Value was {0}".format(val))

    cdef int _write(self, PktWriter w,
                          Py_ssize_t dns_start,
                          dict labels,
                          bint compress=1,
                          bint update=1) except -1:
        """Append this resource record to the shared output buffer.

        rdlength cannot be known until the resource data behind it has been
        written, so it goes out as a placeholder and is patched back into its
        slot afterwards. That is what the old version was approximating when
        it pre-advanced its offset counter by 10 and then reassembled the
        whole record from three pieces. See w_dns_name for dns_start.
        """
        cdef:
            Py_ssize_t rdlen_at, rdata_at

        w_dns_name(w, self._domain_name, dns_start, labels, compress)
        w_u16(w, self.res_type)
        w_u16(w, self.res_class)
        w_u32(w, self.res_ttl)
        rdlen_at = w.n
        w_u16(w, self.res_len)
        rdata_at = w.n
        if self.res_type in (DNSTYPE_NS, DNSTYPE_CNAME, DNSTYPE_PTR):
            w_dns_name(w, self.res_data, dns_start, labels, compress)
        elif self.res_type == DNSTYPE_A:
            w_bytes(w, socket.inet_pton(socket.AF_INET, self.res_data))
        elif self.res_type == DNSTYPE_AAAA:
            w_bytes(w, socket.inet_pton(socket.AF_INET6, self.res_data))
        elif self.res_type == DNSTYPE_SOA:
            w_soa(w, self.res_data, dns_start, labels, compress)
        else:
            w_bytes(w, self.res_data.encode())
        if update:
            self.res_len = <uint16_t>(w.n - rdata_at)
            w_set_u16(w, rdlen_at, self.res_len)
        return 0


@cython.final
cdef class DNS(PKT):
    """ Wrapper for RFC 1035 DNS packet data. Reads and writes.

    """
    def __init__(self, *args, **kwargs):
        self._base_l7(kwargs)
        self.pkt_name = 'DNS'
        self.pq_type, self.query_fields = DNS.query_info()
        cdef:
            bint use_buffer
            array buf
            const unsigned char[:] mv

        use_buffer, buf = self.from_buffer(args, kwargs)

        self._flags = 0
        self.queries = list()
        self.answers = list()
        self.authority = list()
        self.ad = list()
        self.labels = dict()

        if use_buffer:
            mv = buf
            self._parse_message(mv)

        else:
            self.ident = kwargs.get('ident', 0)
            self.query_resp = kwargs.get('query_resp', 0)
            self.op_code = kwargs.get('op_code', 0)
            self.authoritative = kwargs.get('authoritative', 0)
            self.truncated = kwargs.get('truncated', 0)
            self.recursion_requested = kwargs.get('recursion_requested', 0)
            self.recursion_available = kwargs.get('recursion_available', 0)
            self.authentic_data = kwargs.get('authentic_data', 0)
            self.check_disabled = kwargs.get('check_disabled', 0)
            self.resp_code = kwargs.get('resp_code', 0)
            self.query_count = kwargs.get('query_count', 0)
            self.answer_count = kwargs.get('answer_count', 0)
            self.auth_count = kwargs.get('auth_count', 0)
            self.ad_count = kwargs.get('ad_count', 0)

    @classmethod
    def _from_owner(cls, bytes owner, Py_ssize_t start, Py_ssize_t end,
                    dict l7_ports):
        cdef:
            DNS pkt
            const unsigned char[:] mv
            const unsigned char[:] message

        if start < 0 or end < start or end > len(owner):
            raise ValueError('DNS: invalid owner range')

        pkt = cls.__new__(cls)
        pkt.l7_ports = l7_ports
        pkt.pkt_name = 'DNS'
        pkt.pq_type, pkt.query_fields = DNS.query_info()
        pkt._flags = 0
        pkt.queries = list()
        pkt.answers = list()
        pkt.authority = list()
        pkt.ad = list()
        pkt.labels = dict()

        mv = owner
        message = mv[start:end]
        pkt._parse_message(message)
        return pkt

    cdef int _parse_message(self, const unsigned char[:] mv) except -1:
        cdef:
            uint32_t i
            uint16_t offset = 0
            str query_name
            uint16_t query_type, query_class
            tuple resource_args

        # read the first 12 bytes into six unsigned shorts.
        need_bytes(mv, 12, 'DNS')
        self.ident = rd_u16(mv, 0)
        self._flags = rd_u16(mv, 2)
        self.query_count = rd_u16(mv, 4)
        self.answer_count = rd_u16(mv, 6)
        self.auth_count = rd_u16(mv, 8)
        self.ad_count = rd_u16(mv, 10)
        # add those 12 bytes to the offset index.
        offset = 12
        # for each query and or resource record we have parse the data.
        if self.query_count:
            for i in range(self.query_count):
                # read and or update our labels
                query_name = read_dns_name_bytes(mv,
                                                 &offset,
                                                 self.labels
                )
                # unpack the remainder of the query.
                need_bytes(mv, offset + 4, 'DNS')
                query_type = rd_u16(mv, offset)
                query_class = rd_u16(mv, offset + 2)
                self.queries.append(DNSQuery(query_name,
                                               query_type,
                                               query_class))
                offset += 4
        # Now unpack the resources by the 3 remaining types.
        if self.answer_count:
            for _ in range(self.answer_count):
                resource_args = parse_resource(mv,
                                               &offset,
                                               self.labels
                )
                self.answers.append(DNSResource(*resource_args))
        if self.auth_count:
            for _ in range(self.auth_count):
                resource_args = parse_resource(mv,
                                               &offset,
                                               self.labels
                )
                self.authority.append(DNSResource(*resource_args))
        if self.ad_count:
            for _ in range(self.ad_count):
                resource_args = parse_resource(mv,
                                               &offset,
                                               self.labels
                )
                self.ad.append(DNSResource(*resource_args))
        return 0

    @classmethod
    def query_info(cls):
        """
        Used by pcap_query to derive what PKT class ID this class has AND
        what query fields it supports. ANY PKT based class that wants to be
        supported by packets.query.pcap_query's PcapQuery must
        implment this class method and optimaly provide a
        get_field_val(<field_name>) function as well.
        return: uint16_t pq_type, tuple_of_string query_fields"""
        return (DNS_PACKET_TYPE,
                ('dns.ident', 'dns.query_resp', 'dns.op_code',
                 'dns.authoritative',
                 'dns.truncated', 'dns.recursion_requested',
                 'dns.recursion_available',
                 'dns.authentic_data', 'dns.check_disabled',
                 'dns.resp_code',
                 'dns.query_count', 'dns.answer_count', 'dns.auth_count',
                 'dns.ad_count'))


    @classmethod
    def default_ports(cls):
        """
        Used by pcap_query to deterimine what layer 4 ports should be parsed
        by the layer 4 protocols (TCP, UDP) as THIS packet type."""
        return [DNS_PACKET_PORT]


    cpdef object get_field_val(self, str field):
        """ Used to fetch field data values for DNS packets. Does not yet have
            support for retrieving query and resource record values.
            Args:
                :field (str): name of the field
            Returns:
                :object: the value of the field in this packet.
        """
        if field == 'dns.ident':
            return self.ident
        elif field == 'dns.query_resp':
            return self.query_resp
        elif field == 'dns.op_code':
            return self.op_code
        elif field == 'dns.authoritative':
            return self.authoritative
        elif field == 'dns.truncated':
            return self.truncated
        elif field == 'dns.recursion_requested':
            return self.recursion_requested
        elif field == 'dns.recursion_available':
            return self.recursion_available
        elif field == 'dns.authentic_data':
            return self.authentic_data
        elif field == 'dns.check_disabled':
            return self.check_disabled
        elif field == 'dns.resp_code':
            return self.resp_code
        elif field == 'dns.query_count':
            return self.query_count
        elif field == 'dns.answer_count':
            return self.answer_count
        elif field == 'dns.auth_count':
            return self.auth_count
        elif field == 'dns.ad_count':
            return self.ad_count
        else:
            return None

    property query_resp:
        def __get__(self):
            return (self._flags >> 15) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 15)
            elif val == 1:
                set_bit(&self._flags, 15)
            else:
                raise ValueError("DNS query_resp bit must be 0 or 1.")

    property op_code:
        def __get__(self):
            return get_short_nibble(self._flags, 11)

        def __set__(self, unsigned char val):
            if 0 <= val <= 15:
                set_short_nibble(&self._flags, val, 11)
            else:
                raise ValueError("DNS op_code must be between 0 and 15.")

    property authoritative:
        def __get__(self):
            return (self._flags >> 10) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 10)
            elif val == 1:
                set_bit(&self._flags, 10)
            else:
                raise ValueError("DNS authoritative bit must be 0 or 1.")

    property truncated:
        def __get__(self):
            return (self._flags >> 9) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 9)
            elif val == 1:
                set_bit(&self._flags, 9)
            else:
                raise ValueError("DNS truncated bit must be 0 or 1.")

    property recursion_requested:
        def __get__(self):
            return (self._flags >> 8) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 8)
            elif val == 1:
                set_bit(&self._flags, 8)
            else:
                raise ValueError("DNS recursion_requested bit must be 0 or 1.")

    property recursion_available:
        def __get__(self):
            return (self._flags >> 7) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 7)
            elif val == 1:
                set_bit(&self._flags, 7)
            else:
                raise ValueError("DNS recursion_available bit must be 0 or 1.")

    property authentic_data:
        def __get__(self):
            return (self._flags >> 5) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 5)
            elif val == 1:
                set_bit(&self._flags, 5)
            else:
                raise ValueError("DNS authentic_data bit must be 0 or 1.")

    property check_disabled:
        def __get__(self):
            return (self._flags >> 4) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 4)
            elif val == 1:
                set_bit(&self._flags, 4)
            else:
                raise ValueError("DNS check_disabled bit must be 0 or 1.")

    property resp_code:
        def __get__(self):
            return get_short_nibble(self._flags, 0)

        def __set__(self, unsigned char val):
            if 0 <= val <= 15:
                set_short_nibble(&self._flags, val, 0)
            else:
                raise ValueError("DNS resp_code must be between 0 and 15.")

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a DNS packet class instance in network order for 
        writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by UDP to payload classes. UDP supports the 
                following keyword arguments:
            :update (0 or 1): Determines if this DNS instance should
                    re-calculate size values.
            :compress (0 or 1): Compress labels. Default is 1 to compress.
        Returns: 
            :bytes: network order byte string representation of this DNS 
                instance.
        """
        return _serialize(self, kwargs)

    cdef int _write(self, PktWriter w, dict kwargs) except -1:
        """Append this DNS message to a shared buffer.

        DNS is a leaf -- nothing is carried beneath it -- so this is a
        straight walk of the header, the queries and the three resource
        lists. The only thing worth noting is dns_start: compression pointers
        are offsets from the beginning of the DNS message, not of the frame,
        so every name writer is told where the message began and subtracts.
        See PKT._write.
        """
        cdef:
            bint update, compress
            Py_ssize_t dns_start
            dict pack_labels
            DNSQuery query
            DNSResource resource

        update = kwargs.get('update', 0)
        compress = kwargs.get('compress', 1)
        pack_labels = dict()
        dns_start = w.n

        if update:
            self.query_count = len(self.queries)
            self.answer_count = len(self.answers)
            self.auth_count = len(self.authority)
            self.ad_count = len(self.ad)

        w_u16(w, self.ident)
        w_u16(w, self._flags)
        w_u16(w, self.query_count)
        w_u16(w, self.answer_count)
        w_u16(w, self.auth_count)
        w_u16(w, self.ad_count)

        for query in self.queries:
            query._write(w, dns_start, pack_labels, compress)
        # Walked as three loops rather than answers + authority + ad, which
        # allocated and threw away a joined list on every serialization.
        for resource in self.answers:
            resource._write(w, dns_start, pack_labels, compress)
        for resource in self.authority:
            resource._write(w, dns_start, pack_labels, compress)
        for resource in self.ad:
            resource._write(w, dns_start, pack_labels, compress)
        return 0