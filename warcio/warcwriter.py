import zlib

from socket import gethostname

from warcio.utils import Digester, BUFF_SIZE
from warcio.recordbuilder import RecordBuilder

from warcio.statusandheaders import StatusAndHeadersParser, StatusAndHeaders


# ============================================================================
class BaseWARCWriter(RecordBuilder):

    def __init__(self, gzip=True, *args, **kwargs):
        super(BaseWARCWriter, self).__init__(warc_version=kwargs.get('warc_version'),
                                             header_filter=kwargs.get('header_filter'))
        self.gzip = gzip
        self.hostname = gethostname()

        self.parser = StatusAndHeadersParser([], verify=False)

    def write_request_response_pair(self, req, resp, params=None):
        url = resp.rec_headers.get_header('WARC-Target-URI')
        dt = resp.rec_headers.get_header('WARC-Date')

        req.rec_headers.replace_header('WARC-Target-URI', url)
        req.rec_headers.replace_header('WARC-Date', dt)

        resp_id = resp.rec_headers.get_header('WARC-Record-ID')
        if resp_id:
            req.rec_headers.add_header('WARC-Concurrent-To', resp_id)

        self._do_write_req_resp(req, resp, params)

    def write_record(self, record, params=None):  #pragma: no cover
        raise NotImplemented()

    def write_segmented_record(self, record, max_segment_size):  #pragma: no cover
        raise NotImplemented()

    def _do_write_req_resp(self, req, resp, params):  #pragma: no cover
        raise NotImplemented()

    def _write_warc_record(self, out, record):
        if self.gzip:
            out = GzippingWrapper(out)

        http_headers_only = self._prepare_warc_record(record)

        self._write_record_block(out, record, http_headers_only)

    def _prepare_warc_record(self, record):
        """ Normalize a record so that its digests, length and HTTP
        header buffer are all available, mirroring what a plain
        write_record call does. Returns True if only the HTTP headers
        are written as the block (revisit records).
        """
        if record.http_headers:
            record.http_headers.compute_headers_buffer(self.header_filter)

        # Content-Length is None/unknown
        # Fix record by: buffering and recomputing all digests and length
        # (since no length, can't trust existing digests)
        # Also remove content-type for consistent header ordering
        if record.length is None:
            record.rec_headers.remove_header('WARC-Block-Digest')
            if record.rec_type != 'revisit':
                record.rec_headers.remove_header('WARC-Payload-Digest')
            record.rec_headers.remove_header('Content-Type')

            self.ensure_digest(record, block=True, payload=True)

            record.length = record.payload_length

        # ensure digests are set
        else:
            self.ensure_digest(record, block=True, payload=True)

        if record.content_type != None:
            # ensure proper content type
            record.rec_headers.replace_header('Content-Type', record.content_type)

        if record.rec_type == 'revisit':
            http_headers_only = True
        else:
            http_headers_only = False

        # compute Content-Length
        if record.http_headers and record.payload_length >= 0:
            actual_len = 0

            if record.http_headers:
                actual_len = len(record.http_headers.headers_buff)

            if not http_headers_only:
                actual_len += record.payload_length

            record.length = actual_len

        record.rec_headers.replace_header('Content-Length', str(record.length))

        return http_headers_only

    def _write_record_block(self, out, record, http_headers_only):
        # write record headers -- encoded as utf-8
        # WARC headers can be utf-8 per spec
        out.write(record.rec_headers.to_bytes(encoding='utf-8'))

        # write headers buffer, if any
        if record.http_headers:
            out.write(record.http_headers.headers_buff)

        if not http_headers_only:
            try:
                for buf in self._iter_stream(record.raw_stream):
                    out.write(buf)
            finally:
                if hasattr(record, '_orig_stream'):
                    record.raw_stream.close()
                    record.raw_stream = record._orig_stream

        # add two lines
        out.write(b'\r\n\r\n')

        out.flush()

    def _write_segmented_record(self, out, record, max_segment_size):
        """ Write a record, splitting its content block into a series
        of WARC segments if it exceeds max_segment_size.
        """
        http_headers_only = self._prepare_warc_record(record)

        headers_buff = b''
        if record.http_headers:
            headers_buff = record.http_headers.headers_buff

        if http_headers_only:
            payload_length = 0
        elif record.payload_length >= 0:
            payload_length = record.payload_length
        else:
            payload_length = record.length - len(headers_buff)

        block_len = len(headers_buff) + payload_length

        # content block fits: write as an ordinary record
        if block_len <= max_segment_size:
            if self.gzip:
                out = GzippingWrapper(out)

            self._write_record_block(out, record, http_headers_only)
            return

        # the first segment must hold the complete HTTP headers
        # plus at least one byte of body
        room = max_segment_size - len(headers_buff)
        if room < 1:
            raise ValueError(
                'max_segment_size={0} too small: the HTTP headers ({1} '
                'bytes) plus at least one byte of body must fit'.format(
                    max_segment_size, len(headers_buff)))

        # the first segment carries a payload digest for the complete
        # (reassembled) payload; compute if the source record lacks one
        self._ensure_full_payload_digest(record)

        first_id = record.rec_headers.get_header('WARC-Record-ID')
        warc_date = record.rec_headers.get_header('WARC-Date')
        protocol = record.rec_headers.protocol

        segment_number = 1
        remaining = payload_length

        while remaining > 0:
            if segment_number == 1:
                want = room
                seg_headers = self._first_segment_headers(record)
            else:
                want = min(max_segment_size, remaining)
                seg_headers = self._continuation_headers(
                    protocol, warc_date, segment_number, first_id)

            chunk = self._read_exact(record.raw_stream, want)
            segment_block = headers_buff + chunk if segment_number == 1 else chunk

            block_digester = self._create_digester()
            block_digester.update(segment_block)
            seg_headers.add_header('WARC-Block-Digest', str(block_digester))
            seg_headers.replace_header('Content-Length',
                                       str(len(segment_block)))

            remaining -= len(chunk)
            if remaining == 0:
                seg_headers.add_header('WARC-Segment-Total-Length',
                                       str(block_len))

            # each segment is its own gzip member when gzip is enabled
            if self.gzip:
                segment_out = GzippingWrapper(out)
            else:
                segment_out = out

            segment_out.write(seg_headers.to_bytes(encoding='utf-8'))
            segment_out.write(segment_block)
            segment_out.write(b'\r\n\r\n')
            segment_out.flush()

            segment_number += 1

    def _ensure_full_payload_digest(self, record):
        """ Ensure WARC-Payload-Digest covers the complete payload.
        Unlike ensure_digest(), this also applies to record types that
        normally omit a payload digest, since the first segment of a
        segmented record series must always carry it.
        """
        if record.rec_headers.get_header('WARC-Payload-Digest'):
            return

        payload_digester = self._create_digester()

        try:
            pos = record.raw_stream.tell()
            record.raw_stream.seek(pos)
            temp_file = None
        except:
            pos = 0
            temp_file = self._create_temp_file()

        for buf in self._iter_stream(record.raw_stream):
            payload_digester.update(buf)
            if temp_file:
                temp_file.write(buf)

        if temp_file:
            record.payload_length = temp_file.tell()
            temp_file.seek(0)
            record._orig_stream = record.raw_stream
            record.raw_stream = temp_file
        else:
            record.raw_stream.seek(pos)

        record.rec_headers.add_header('WARC-Payload-Digest',
                                      str(payload_digester))

    @staticmethod
    def _first_segment_headers(record):
        src = record.rec_headers
        seg_headers = StatusAndHeaders(src.statusline,
                                       list(src.headers),
                                       protocol=src.protocol)
        seg_headers.remove_header('Content-Length')
        seg_headers.remove_header('WARC-Block-Digest')
        seg_headers.remove_header('WARC-Segment-Number')
        seg_headers.remove_header('WARC-Segment-Origin-ID')
        seg_headers.remove_header('WARC-Segment-Total-Length')
        seg_headers.add_header('WARC-Segment-Number', '1')
        return seg_headers

    def _continuation_headers(self, protocol, warc_date,
                              segment_number, first_id):
        seg_headers = StatusAndHeaders('', [], protocol=protocol)
        seg_headers.add_header('WARC-Type', 'continuation')
        seg_headers.add_header('WARC-Record-ID', self._make_warc_id())
        seg_headers.add_header('WARC-Date', warc_date)
        seg_headers.add_header('WARC-Segment-Number', str(segment_number))
        seg_headers.add_header('WARC-Segment-Origin-ID', first_id)
        return seg_headers

    @staticmethod
    def _read_exact(stream, length):
        parts = []
        while length > 0:
            buff = stream.read(min(length, BUFF_SIZE))
            if not buff:
                break
            parts.append(buff)
            length -= len(buff)
        return b''.join(parts)


# ============================================================================
class GzippingWrapper(object):
    def __init__(self, out):
        self.compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS + 16)
        self.out = out

    def write(self, buff):
        #if isinstance(buff, str):
        #    buff = buff.encode('utf-8')
        buff = self.compressor.compress(buff)
        self.out.write(buff)

    def flush(self):
        buff = self.compressor.flush()
        self.out.write(buff)
        self.out.flush()


# ============================================================================
class WARCWriter(BaseWARCWriter):
    def __init__(self, filebuf, *args, **kwargs):
        super(WARCWriter, self).__init__(*args, **kwargs)
        self.out = filebuf

    def write_record(self, record, params=None):
        self._write_warc_record(self.out, record)

    def write_segmented_record(self, record, max_segment_size):
        self._write_segmented_record(self.out, record, max_segment_size)

    def _do_write_req_resp(self, req, resp, params):
        self._write_warc_record(self.out, resp)
        self._write_warc_record(self.out, req)


# ============================================================================
class BufferWARCWriter(WARCWriter):
    def __init__(self, *args, **kwargs):
        out = self._create_temp_file()
        super(BufferWARCWriter, self).__init__(out, *args, **kwargs)

    def get_contents(self):
        pos = self.out.tell()
        self.out.seek(0)
        buff = self.out.read()
        self.out.seek(pos)
        return buff

    def get_stream(self):
        self.out.seek(0)
        return self.out


