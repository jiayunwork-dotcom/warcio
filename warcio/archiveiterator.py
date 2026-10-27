from io import BytesIO

from warcio.bufferedreaders import DecompressingBufferedReader

from warcio.exceptions import ArchiveLoadFailed
from warcio.recordloader import ArcWarcRecordLoader
from warcio.statusandheaders import StatusAndHeaders

from warcio.utils import BUFF_SIZE

import sys
import six

# ============================================================================
class UnseekableYetTellable:
    def __init__(self, fh):
        self.fh = fh
        self.offset = 0

    def tell(self):
        return self.offset

    def read(self, size=-1):
        result = self.fh.read(size)
        self.offset += len(result)
        return result

# ============================================================================
class PendingSegmentedRecord(object):
    """ Holds the physical records (and their content block bytes) of
    a segmented record series whose final segment has not been seen yet.
    """

    def __init__(self, first_record, first_block, member_info):
        self.first_record = first_record
        self.blocks = [first_block]
        self.records = [first_record]
        self.member_info = member_info

    def add(self, record, block):
        self.records.append(record)
        self.blocks.append(block)

    def content_length_sum(self):
        total = 0
        for record in self.records:
            total += int(record.rec_headers.get_header('Content-Length'))
        return total

    def digest_checkers(self):
        return [record.digest_checker for record in self.records
                if record.digest_checker is not None]

# ============================================================================
class ArchiveIterator(six.Iterator):
    """ Iterate over records in WARC and ARC files, both gzip chunk
    compressed and uncompressed

    The indexer will automatically detect format, and decompress
    if necessary.

    """

    GZIP_ERR_MSG = """
    ERROR: non-chunked gzip file detected, gzip block continues
    beyond single record.

    This file is probably not a multi-member gzip but a single gzip file.

    To allow seek, a gzipped {1} must have each record compressed into
    a single gzip member and concatenated together.

    This file is likely still valid and can be fixed by running:

    warcio recompress <path/to/file> <path/to/new_file>

"""

    INC_RECORD = """\
    WARNING: Record not followed by newline, perhaps Content-Length is invalid
    Offset: {0}
    Remainder: {1}
"""

    def __init__(self, fileobj, no_record_parse=False,
                 verify_http=False, arc2warc=False,
                 ensure_http_headers=False, block_size=BUFF_SIZE,
                 check_digests=False):

        self.fh = fileobj

        self.loader = ArcWarcRecordLoader(verify_http=verify_http,
                                          arc2warc=arc2warc)
        self.known_format = None

        self.mixed_arc_warc = arc2warc

        self.member_info = None
        self.no_record_parse = no_record_parse
        self.ensure_http_headers = ensure_http_headers

        try:
            self.offset = self.fh.tell()
        except:
            self.fh = UnseekableYetTellable(self.fh)
            self.offset = self.fh.tell()

        self.reader = DecompressingBufferedReader(self.fh,
                                                  block_size=block_size)

        self.next_line = None

        self.check_digests = check_digests
        self.err_count = 0
        self.record = None

        self.the_iter = self._iterate_records()

    def __iter__(self):
        return self.the_iter

    def __next__(self):
        return six.next(self.the_iter)

    def close(self):
        self.record = None
        if self.reader:
            self.reader.close_decompressor()
            self.reader = None

    def _iterate_records(self):
        """ iterate over each record
        """
        raise_invalid_gzip = False
        empty_record = False

        # incomplete segmented record series, keyed by the first
        # segment's WARC-Record-ID (the continuations'
        # WARC-Segment-Origin-ID)
        pending_segments = {}

        while True:
            try:
                self.record = self._next_record(self.next_line)
                if raise_invalid_gzip:
                    self._raise_invalid_gzip_err()

                kind, key = self._classify_segment(self.record)

                if kind == 'segment-first':
                    # buffer the first segment, it is not yielded on its own
                    block = self._read_record_block(self.record)
                    self.read_to_end()
                    pending_segments[key] = PendingSegmentedRecord(
                        self.record, block, self.member_info)

                elif kind == 'segment-continuation' and key in pending_segments:
                    # part of a known segmented record series
                    block = self._read_record_block(self.record)
                    self.read_to_end()

                    series = pending_segments[key]
                    series.add(self.record, block)

                    if self.record.rec_headers.get_header(
                            'WARC-Segment-Total-Length') is not None:
                        # final segment: merge the whole series
                        del pending_segments[key]
                        self.record = self._merge_segmented_record(series)
                        # the merged record is located at the first segment
                        self.member_info = series.member_info
                        yield self.record

                else:
                    # ordinary record, or an orphan continuation whose
                    # first segment is not in this stream: yield as-is
                    yield self.record

            except EOFError:
                empty_record = True

            self.read_to_end()

            if self.reader.decompressor:
                # if another gzip member, continue
                if self.reader.read_next_member():
                    continue

                # if empty record, then we're done
                elif empty_record:
                    break

                # otherwise, probably a gzip
                # containing multiple non-chunked records
                # raise this as an error
                else:
                    raise_invalid_gzip = True

            # non-gzip, so we're done
            elif empty_record:
                break

        self.close()

    def _raise_invalid_gzip_err(self):
        """ A gzip file with multiple ARC/WARC records, non-chunked
        has been detected. This is not valid for replay, so notify user
        """
        frmt = 'warc/arc'
        if self.known_format:
            frmt = self.known_format

        frmt_up = frmt.upper()

        msg = self.GZIP_ERR_MSG.format(frmt, frmt_up)
        raise ArchiveLoadFailed(msg)

    def _consume_blanklines(self):
        """ Consume blank lines that are between records
        - For warcs, there are usually 2
        - For arcs, may be 1 or 0
        - For block gzipped files, these are at end of each gzip envelope
          and are included in record length which is the full gzip envelope
        - For uncompressed, they are between records and so are NOT part of
          the record length

          count empty_size so that it can be subtracted from
          the record length for uncompressed

          if first line read is not blank, likely error in WARC/ARC,
          display a warning
        """
        empty_size = 0
        first_line = True

        while True:
            line = self.reader.readline()
            if len(line) == 0:
                return None, empty_size

            stripped = line.rstrip()

            if len(stripped) == 0 or first_line:
                empty_size += len(line)

                if len(stripped) != 0:
                    # if first line is not blank,
                    # likely content-length was invalid, display warning
                    err_offset = self.fh.tell() - self.reader.rem_length() - empty_size
                    sys.stderr.write(self.INC_RECORD.format(err_offset, line))
                    self.err_count += 1

                first_line = False
                continue

            return line, empty_size

    def read_to_end(self, record=None):
        """ Read remainder of the stream
        If a digester is included, update it
        with the data read
        """

        # no current record to read
        if not self.record:
            return None

        # already at end of this record, don't read until it is consumed
        if self.member_info:
            return None

        curr_offset = self.offset

        while True:
            b = self.record.raw_stream.read(BUFF_SIZE)
            if not b:
                break

        """
        - For compressed files, blank lines are consumed
          since they are part of record length
        - For uncompressed files, blank lines are read later,
          and not included in the record length
        """
        #if self.reader.decompressor:
        self.next_line, empty_size = self._consume_blanklines()

        self.offset = self.fh.tell() - self.reader.rem_length()
        #if self.offset < 0:
        #    raise Exception('Not Gzipped Properly')

        if self.next_line:
            self.offset -= len(self.next_line)

        length = self.offset - curr_offset

        if not self.reader.decompressor:
            length -= empty_size

        self.member_info = (curr_offset, length)
        #return self.member_info
        #return next_line

    def get_record_offset(self):
        if not self.member_info:
            self.read_to_end()

        return self.member_info[0]

    def get_record_length(self):
        if not self.member_info:
            self.read_to_end()

        return self.member_info[1]

    def _next_record(self, next_line):
        """ Use loader to parse the record from the reader stream
        Supporting warc and arc records
        """
        record = self.loader.parse_record_stream(self.reader,
                                                 next_line,
                                                 self.known_format,
                                                 self.no_record_parse,
                                                 self.ensure_http_headers,
                                                 self.check_digests)

        self.member_info = None

        # Track known format for faster parsing of other records
        if not self.mixed_arc_warc:
            self.known_format = record.format

        return record

    def _classify_segment(self, record):
        """ Determine whether a physical record is part of a segmented
        record series.

        Returns ('segment-first', record-id) for the first segment,
        ('segment-continuation', origin-id) for a continuation record
        and (None, None) for ordinary records (including continuation
        records whose first segment is not in this stream).
        """
        origin_id = record.rec_headers.get_header('WARC-Segment-Origin-ID')
        if record.rec_type == 'continuation' and origin_id:
            return 'segment-continuation', origin_id

        if record.rec_headers.get_header('WARC-Segment-Number') is not None:
            record_id = record.rec_headers.get_header('WARC-Record-ID')
            return 'segment-first', record_id

        return None, None

    @staticmethod
    def _read_record_block(record):
        """ Read the complete content block of a physical record into
        memory. Reading the block also triggers the per-segment block
        digest verification.
        """
        if record.http_headers:
            # the HTTP headers have already been consumed from
            # raw_stream, re-add their serialized form
            if not record.http_headers.headers_buff:
                record.http_headers.compute_headers_buffer()
            return record.http_headers.headers_buff + record.raw_stream.read()

        return record.raw_stream.read()

    def _merge_segmented_record(self, series):
        """ Merge a completed segmented record series into a single
        ArcWarcRecord, using the first segment's headers and the
        concatenated content blocks of all segments.
        """
        final_record = series.records[-1]
        declared_length = final_record.rec_headers.get_header(
            'WARC-Segment-Total-Length')

        try:
            declared_length = int(declared_length)
        except (TypeError, ValueError):
            raise ArchiveLoadFailed(
                'Invalid WARC-Segment-Total-Length: {0}'.format(
                    declared_length))

        actual_length = series.content_length_sum()
        if declared_length != actual_length:
            first_id = series.first_record.rec_headers.get_header(
                'WARC-Record-ID')
            raise ArchiveLoadFailed(
                'Segmented record {0}: sum of segment lengths {1} does '
                'not match WARC-Segment-Total-Length {2}'.format(
                    first_id, actual_length, declared_length))

        first_headers = series.first_record.rec_headers
        # merged record uses the first segment's headers, without the
        # segmentation marker and the per-segment block digest
        rec_headers = StatusAndHeaders(first_headers.statusline,
                                       list(first_headers.headers),
                                       protocol=first_headers.protocol)
        rec_headers.remove_header('WARC-Segment-Number')
        rec_headers.remove_header('WARC-Block-Digest')
        rec_headers.replace_header('Content-Length', str(actual_length))

        block = b''.join(series.blocks)

        # re-parse the assembled record so that HTTP headers and digests
        # are handled exactly as for ordinary records
        stream = BytesIO(rec_headers.to_bytes(encoding='utf-8') +
                         block + b'\r\n\r\n')

        merged = self.loader.parse_record_stream(
            stream,
            known_format='warc',
            no_record_parse=self.no_record_parse,
            ensure_http_headers=self.ensure_http_headers,
            check_digests=self.check_digests)

        self._combine_segment_digest_results(merged, series)

        return merged

    @staticmethod
    def _combine_segment_digest_results(merged, series):
        """ Propagate block digest failures of the individual segments
        onto the merged record's digest checker.
        """
        for checker in series.digest_checkers():
            if checker.passed is False:
                merged.digest_checker._problem.extend(checker.problems)
                merged.digest_checker._passed = False


# ============================================================================
class WARCIterator(ArchiveIterator):
    def __init__(self, *args, **kwargs):
        super(WARCIterator, self).__init__(*args, **kwargs)
        self.known_format = 'warc'


# ============================================================================
class ARCIterator(ArchiveIterator):
    def __init__(self, *args, **kwargs):
        super(ARCIterator, self).__init__(*args, **kwargs)
        self.known_format = 'arc'



