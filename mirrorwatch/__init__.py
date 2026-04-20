from collections.abc import Iterator
from contextlib import ContextDecorator
import errno
import html
from html.parser import HTMLParser
import select
import socket

import urllib3.util

SOCKET_IOSIZE = 1024 * 8

class HostNetInfo:
	def __init__ (self):
		self.host = ""
		self.ipaddr = ""
		self.route = ""
		self.origin = "" # aka. AS number
		self.descr = "" # usually the first line being the "network name"

class MirrorInfo:
	def __init__ (self):
		self.country = ""
		self.name = ""
		self.mirror_host = set[str]()
		self.hnlist = list[HostNetInfo]()

class PageParser (HTMLParser):
	def __init__ (self):
		super().__init__()
		self._at_row = False
		self._at_td = False
		self._at_a = False
		self._at_name = False
		self._cur_td_idx = 0
		self._cur_info: MirrorInfo = None
		self.result = list[MirrorInfo]()

	def handle_starttag(self, tag, attrs):
		def _get_attr (name: str) -> str:
			nonlocal attrs
			for k, v in attrs:
				if k == name:
					return v

		if self._at_row:
			if tag == 'td':
				self._cur_td_idx += 1
				self._at_td = True
				self._at_a = self._cur_td_idx == 3
		elif tag == 'tr' and _get_attr('class') == 'mirror-row':
			self._at_row = True
			self._at_td = False
			self._cur_td_idx = -1
			self._cur_info = MirrorInfo()

		if tag == 'a':
			if self._at_a:
				href = _get_attr('href')
				# The mirror name has no format. The hostname has to be
				# retrieved from <a> tags.
				#
				# urllib3 is used here because Python's own urllib is retardedly
				# pedantic. Almost all systems should have this lib.
				if href:
					url = urllib3.util.parse_url(href)
					if url.hostname: self._cur_info.mirror_host.add(url.hostname)
			elif self._cur_td_idx == 2:
				self._at_name = True

	def handle_endtag(self, tag):
		if not self._at_row:
			return

		match tag:
			case 'tr':
				self._at_td = self._at_row = False
				self.result.append(self._cur_info)
				self._cur_info = None
			case 'td':
				self._at_td = False
				self._at_a = False
			case 'a':
				self._at_name = False

	def handle_data(self, data):
		if self._at_td and self._at_row and self._cur_td_idx == 0:
			self._cur_info.country = html.escape(data).strip()
		elif self._at_name:
			self._cur_info.name = html.escape(data).strip()

class WhoisQueryConnection (ContextDecorator):
	"""
	Query whois db in pipeline

	https://www.radb.net/support/informational/query.html
	> Please note: The RADb WHOIS service is rate-limited. For large queries,
	> we recommend using the RADb API Programmatic access is considered abuse
	> of the service.

	Yeah, but ...

	- radb.db file on their FTP server is not a full db
	- all RIR db's around the world amount to about 6 GB file and probably even
	  more when loaded to a Python program
	- There's no '!r' equivalent in the REST API

	So, might as well just abuse the service and hope for the best(please don't
	sue me).

	Pipelining is essential because there's 500+ IP addresses to query.
	However, The "traditional" Python APIs including requests or http.client
	do not HTTP support pipelining. The maintainer of aiohttp decided not to
	implement the feature. Rawdogging the TCP WHOIS protocol was the only way
	to speed things up in Python.

	Sorry, folks. Hitting the radb whois server was the only viable option.

	When the push comes to shove(ie. RADb blacklists/ratelimits whois queries),
	I can always run my own whois DB(with blackjack and hookers).
	"""
	def __init__(self, dbhost = 'whois.radb.net', port = 43):
		super().__init__()
		self._dbhost = dbhost
		self._port = port
		self._conn: socket.socket = None
		self._iosize = 0
		self.retries = 3
		self.timeout = 30.0

	def _ensure_conn (self):
		if self._conn is not None:
			return
		self._conn = socket.socket(-1, socket.SOCK_STREAM, socket.IPPROTO_TCP)
		self._conn.settimeout(float(self.timeout))
		self._conn.connect((self._dbhost, self._port,))
		self._conn.send('!!\n'.encode('ascii'))
		self._conn.settimeout(0.0)

		try:
			bufsize = self._conn.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
			self._iosize = max(SOCKET_IOSIZE, bufsize)
		except OSError:
			self._iosize = SOCKET_IOSIZE

	def _destroy_conn (self):
		if self._conn is None:
			return
		self._conn.close()
		self._conn = None

	def __enter__ (self):
		return self

	def __exit__ (self, *exc):
		self._destroy_conn()
		return False

	"""
	Useful code that could help understand this code:
	https://github.com/irrdnet/irrd/blob/main/irrd/server/whois/query_response.py

	Yes! This is a python program banging another python program.
	"""
	def query_routes (self, hnlist: list[HostNetInfo]):
		tries = 0
		cnt_sent = 0
		cnt_recv = 0
		leftover = bytes()
		recv_buf = bytes()
		def parse_answer (data: bytes, out: HostNetInfo):
			if len(data) == 0:
				raise ValueError('empty response from IRRd')
			if data[0] == ord('%'):
				out.origin = ''
				out.descr = ''
				out.route = ''
				return

			# ignore the following records if any
			sep = data.find(b'\n\n')
			if sep >= 0:
				data = data[:sep]

			for line in data.decode('utf-8', 'replace').splitlines():
				p = [ e.strip() for e in line.split(':', 1) ]
				if len(p) != 2:
					continue
				k = p[0]
				v = p[1]
				match k:
					case 'route' | 'route6': out.route = v
					case 'origin': out.origin = v.upper()
					case 'descr': out.descr = out.descr or v
		"""
		Using RIPE mode here instead of IRRd mode because the answer header
		cannot be relied upon. See https://github.com/irrdnet/irrd/issues/1019
		"""
		def do_send ():
			nonlocal cnt_sent, leftover

			if leftover:
				l = self._conn.send(leftover)
				leftover = leftover[l:]
				if leftover:
					return

			if cnt_sent >= len(hnlist):
				return

			try:
				msg = '-l %s\n' % (hnlist[cnt_sent].ipaddr,)
				data = msg.encode('ascii')
				l = self._conn.send(data)
				leftover = data[l:]
				cnt_sent += 1
				if leftover:
					return
			except OSError as e:
				if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
					return
				raise e
		def do_recv ():
			nonlocal cnt_recv, recv_buf, hnlist

			buf = self._conn.recv(self._iosize)
			if not buf:
				raise EOFError("unexpected EOF")
			recv_buf += buf
			while recv_buf:
				sep = recv_buf.find(b'\n\n\n')
				if sep < 0:
					return
				segment = recv_buf[:sep]
				parse_answer(segment, hnlist[cnt_recv])
				recv_buf = recv_buf[sep + 3:]
				cnt_recv += 1
		def do_relay ():
			nonlocal cnt_sent, cnt_recv, leftover
			fd = self._conn.fileno()

			while True:
				rlist = [ fd ] if cnt_recv < cnt_sent else []
				wlist = [ fd ] if leftover or cnt_sent < len(hnlist) else []

				if not (rlist or wlist):
					break

				has_r, has_w, _ = select.select(rlist, wlist, [], self.timeout)
				if not (has_r or has_w):
					raise TimeoutError
				if has_r: do_recv()
				if has_w: do_send()

		while cnt_recv < len(hnlist):
			try:
				self._ensure_conn()
				cnt_sent = cnt_recv
				do_relay()
				break
			except OSError, TimeoutError, EOFError:
				tries += 1
				self._destroy_conn()
				leftover = bytes()
				if tries >= self.retries:
					raise
		assert cnt_sent == cnt_recv
