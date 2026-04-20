import copy
import traceback
from typing import Any, Iterable
import contextlib
import hashlib
import io
import os
import tempfile
import datetime
import random

import xml.etree.ElementTree as ET
import psycopg2
import requests

from metahealth import *
from mirrorwatch import HostNetInfo, WhoisQueryConnection

DEFAULT_USER_AGENT = 'libdnf (Fedora {rnd}; server; Linux.x86_64)'
XMLNS_ML = '{http://www.metalinker.org/}'
XMLNS_RM = '{http://linux.duke.edu/metadata/repo}'
XMLNS_RPM = '{http://linux.duke.edu/metadata/rpm}'
XMLNS_MM0 = '{http://fedorahosted.org/mirrormanager}'
MAX_CONTENT_LEN = 128 * 1024 * 1024

DEFAULT_BGP_INTERVAL = 86400
DEFAULT_BGP_RETAIN = 31104000
DEFAULT_RUN_RETAIN = 31104000

class Context (contextlib.ContextDecorator):
	def __init__ (self, conf: dict[str, Any]):
		self.conf = conf

		self.db = None
		self.http_session = None
		try:
			self.db = psycopg2.connect(**conf['db'])
			self.http_session = requests.Session()
		except:
			if self.db is not None:
				self.db.close()
			if self.http_session is not None:
				self.http_session.close()
			raise

		self.objmap = dict[str, FileObject]()
		self.collated = dict[str, list[FileMeta]]()
		self.asmap = dict[str, int]()
		self.run_start: datetime.datetime = None
		self.run_end: datetime.datetime = None

		# never cache User-agent, you `dop`es
		ua_fmt: str = conf.get('user-agent', DEFAULT_USER_AGENT)
		ua = ua_fmt.format(rnd=random.randint(40, 100))
		self.http_session.headers['User-Agent'] = ua

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc, tb):
		if self.db is not None:
			self.db.close()
		if self.http_session is not None:
			self.http_session.close()

		return False

class FileMeta:
	def __init__ (self):
		self.ts: int = None
		self.size: int = None
		self.hashmap = dict[str, str]()

class FileObject (contextlib.ContextDecorator):
	def __init__ (self, tmpfile: bool):
		self.resolved: str = None
		self.status: int = None
		self.content_len: int = None
		self.size: int = 0
		self.ts: int = None
		self.hashmap = dict[str, str]()
		self.transfer_time: int = None
		self.tmpfile: tempfile.TemporaryFile = None

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc, tb):
		if self.tmpfile is not None:
			self.tmpfile.close()
		return False

def mkhashmatrix (): return [hashlib.new('sha256'), hashlib.new('sha512')]

def parse_alternate (tag) -> FileMeta:
	ret = FileMeta()

	ts = tag.findall(f'./{XMLNS_MM0}timestamp')
	assert(len(ts) == 1)
	size = tag.findall(f'./{XMLNS_ML}size')
	assert(len(size) == 1)

	ret.ts = int(ts[0].text)
	ret.size = int(size[0].text)

	assert((ret.ts is None or ret.ts > 0) and (ret.size is None or ret.size > 0))

	for hash in tag.findall(f'./{XMLNS_ML}verification/{XMLNS_ML}hash'):
		type = hash.get('type')
		assert(type)

		prev = ret.hashmap.setdefault(type, hash.text)
		assert(prev == hash.text)

	return ret

def pull_file (ctx: Context, url: str, tmpfile: bool) -> FileObject:
	fo = FileObject(tmpfile)
	hm = mkhashmatrix()
	def close_tmpfile ():
		if fo.tmpfile is None:
			return
		fo.tmpfile.close()
		fo.tmpfile = None

	t_start = datetime.datetime.now(datetime.timezone.utc)
	try:
		with ctx.http_session.get(url, allow_redirects=True, stream=True) as r:
			fo.status = r.status_code
			try:
				# The maintainer of requests lib has their head stuck in their own
				# arse to think that this is a useless feature. How unfortunate.
				#
				# https://github.com/psf/requests/issues/2158
				# https://github.com/urllib3/urllib3/issues/400
				# https://github.com/urllib3/urllib3/issues/2156
				# https://github.com/urllib3/urllib3/issues/400?issue=urllib3%7Curllib3%7C439
				# https://github.com/urllib3/urllib3/issues/1071
				fo.resolved = str(r.raw._fp.fp.raw._sock.getpeername()[0])
			except:
				pass

			if not r.ok:
				return fo
			else:
				fo.tmpfile = tempfile.TemporaryFile()

			raw = r.headers.get('Last-Modified')
			if raw is not None:
				fo.ts = parse_last_modified(raw)

			raw = r.headers.get('Content-Length')
			if raw is not None:
				fo.content_len = int(raw)
				if fo.content_len > MAX_CONTENT_LEN:
					raise EOFError('file too large')
				try:
					if tmpfile and fo.content_len > 0:
						fd = fo.tmpfile.fileno()
						os.posix_fallocate(fd, 0, fo.content_len)
						os.posix_fadvise(fd, 0, fo.content_len,
								 os.POSIX_FADV_SEQUENTIAL)
				except:
					pass

			for chunk in r.iter_content(chunk_size=io.DEFAULT_BUFFER_SIZE):
				for h in hm:
					h.update(chunk)

				fo.size += len(chunk)
				if fo.size > MAX_CONTENT_LEN:
					raise EOFError('file too large')

				if fo.tmpfile is not None:
					fo.tmpfile.write(chunk)

			for h in hm:
				fo.hashmap[h.name] = h.hexdigest()
	except:
		close_tmpfile()
	finally:
		t_end = datetime.datetime.now(datetime.timezone.utc)
		dt = t_end - t_start
		fo.transfer_time = int(dt / datetime.timedelta(microseconds=1))

	return fo

def pull_metalink (ctx: Context) -> dict[str, list[FileMeta]]: # filename: list[FileMeta]
	url = ctx.conf['metalink']
	ret = dict[str, list[FileMeta]]()

	with pull_file(ctx, url, True) as fo:
		ctx.objmap['metalink'] = fo
		if fo.tmpfile is None:
			return None

		fo.tmpfile.seek(0)
		doc = ET.parse(fo.tmpfile).getroot()
		assert(doc.tag == f'{XMLNS_ML}metalink')

		files = doc.findall(f'./{XMLNS_ML}files')
		assert(len(files) == 1)
		for file in files[0].findall(f'./{XMLNS_ML}file'):
			name = file.get('name')
			assert(name)
			l = ret.setdefault(name, list[FileMeta]())
			assert(not l)

			l.append(parse_alternate(file))
			for alt in file.findall(f'./{XMLNS_MM0}alternates/{XMLNS_MM0}alternate'):
				l.append(parse_alternate(alt))

	return ret

def parse_repomd (ctx: Context, f: io.FileIO) -> dict[str, list[FileMeta]]: # filename: list[FileMeta]
	ret = dict[str, list[FileMeta]]()

	f.seek(0)
	doc = ET.parse(f).getroot()
	assert(doc.tag == f'{XMLNS_RM}repomd')

	for data in doc.findall(f'./{XMLNS_RM}data'):
		fm = FileMeta()
		l = [fm]

		# location
		loc = data.findall(f'./{XMLNS_RM}location')
		assert(len(loc) == 1)
		loc = loc[0].get('href')
		assert(loc)

		prev = ret.setdefault(loc, l)
		assert(prev == l)

		for checksum in data.findall(f'./{XMLNS_RM}checksum'):
			type = checksum.get('type')
			hash = checksum.text
			prev = fm.hashmap.setdefault(type, hash)
			assert(prev == hash)

		# size
		size = data.findall(f'./{XMLNS_RM}size')
		assert(len(size) == 1)
		fm.size = int(size[0].text)
		assert(fm.size >= 0)

		# timestamp
		ts = data.findall(f'./{XMLNS_RM}timestamp')
		assert(len(ts) == 1)
		fm.ts = int(ts[0].text)
		assert(fm.ts >= 0)

	return ret

EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
HTTP_TS_FMT = [
	"%a, %d %b %Y %H:%M:%S",	# IMF-fixdate
	"%A, %d-%b-%y %H:%M:%S",	# rfc850-date
	# don't accept ts without timezone info. Life's too short to handle that case
	# "%a %b %d %H:%M:%S %Y",		# asctime-date
]

def parse_last_modified (x: str) -> int | None:
	if not (x.endswith('GMT') or x.endswith('UTC')):
		return None
	x = x[:-3].strip()

	for fmt in HTTP_TS_FMT:
		try:
			dt = datetime.datetime.strptime(x, fmt)
			dt = dt.replace(tzinfo=datetime.timezone.utc)
			ts = int((dt - EPOCH).total_seconds())
			if ts < 0:
				continue
			return ts
		except:
			pass

	return None

def validate_file (ctx: Context, fo: FileObject, ifm: Iterable[FileMeta]) -> FileMeta:
	for fm in ifm:
		if fm.size != fo.size:
			continue

		for type, hash in fm.hashmap.items():
			if type.startswith('md'):
				continue
			if type.startswith('sha') and int(type[3:]) < 256:
				continue

			ch = fo.hashmap.get(type)
			if (ch is not None) and (ch == hash):
				return fm

	return None

def collect_on_repodata (ctx: Context):
	baseurl = ctx.conf['baseurl']
	if not baseurl.endswith('/'):
		baseurl += '/'

	# pull metalink to get recent hashes
	meta = pull_metalink(ctx)
	if meta is None:
		return
	ctx.collated.update(meta)

	# pull repomd and validate
	for file, fml in meta.items():
		with pull_file(ctx, f'{baseurl}repodata/{file}', True) as fo:
			ctx.objmap[file] = fo

			if fo.tmpfile is None:
				continue

			fm = validate_file(ctx, fo, fml)
			if fm is None:
				continue
			filemap = parse_repomd(ctx, fo.tmpfile)

		assert(not set(ctx.collated.keys()).intersection(filemap.keys()))
		ctx.collated.update(filemap)

		# pull files and validate
		for href, fml in filemap.items():
			assert(href not in ctx.objmap)
			ctx.objmap[href] = pull_file(ctx, baseurl + href, False)

def resolve_asn (ctx: Context, hosts: Iterable[HostNetInfo]):
	with WhoisQueryConnection() as wqc:
		wqc.query_routes(hosts)

def select_last_bgp_by_addr (ctx: Context, addr: str) -> tuple[HostNetInfo, datetime.datetime]:
	q = '''SELECT "asn", "route", "ts" FROM "bgp" WHERE addr = %s ORDER BY "rid" DESC LIMIT 1'''

	with ctx.db.cursor() as c:
		c.execute(q, (addr,))
		r = c.fetchone()
		if r:
			ret = HostNetInfo()
			ret.ipaddr = addr
			ret.origin = 'AS' + str(r[0])
			ret.route = str(r[1])
			return (ret, r[2].replace(tzinfo=datetime.timezone.utc), )

	return (None, None,)

def insert_into_bgp (ctx: Context, data: Iterable[HostNetInfo], ts: datetime.datetime):
	q = '''INSERT INTO "bgp" ("addr", "route", "asn", "desc", "ts") VALUES (%s, cidr %s, %s, %s, %s)'''

	assert(ts.tzinfo == datetime.timezone.utc)

	with ctx.db.cursor() as c:
		for hni in data:
			c.execute(q, (hni.ipaddr, hni.route, int(hni.origin[2:]), hni.descr[:255], ts, ))

def resolve_hosts (ctx: Context):
	hosts = set[str]()
	last_asmap = dict[str, HostNetInfo]()
	to_resolve = list[HostNetInfo]()
	to_insert = list[HostNetInfo]()

	# filter dupes
	for _, fo in ctx.objmap.items():
		if fo.resolved is None: continue
		hosts.add(fo.resolved)

	now = datetime.datetime.now(datetime.timezone.utc)
	for h in hosts:
		hni, ts = select_last_bgp_by_addr(ctx, h)
		if hni is None:
			hni = HostNetInfo()
			hni.ipaddr = h
			to_resolve.append(copy.deepcopy(hni))
			continue
		last_asmap[h] = hni

		dt = (now - ts)
		if int(dt / datetime.timedelta(seconds=1)) < DEFAULT_BGP_INTERVAL:
			continue

		to_resolve.append(copy.deepcopy(hni))

	if to_resolve:
		try:
			resolve_asn(ctx, to_resolve)
		except Exception as e:
			traceback.print_exception(e)
		else:
			now = datetime.datetime.now(datetime.timezone.utc)

			for b in to_resolve:
				a = last_asmap.get(b.ipaddr)
				if a is not None and a.origin == b.origin and a.route == b.route:
					continue
				to_insert.append(b)

			if to_insert:
				insert_into_bgp(ctx, to_insert, now)

def insert_into_run (ctx: Context) -> int:
	q = '''INSERT INTO "runs" ("metalink", "baseurl", "run_start", "run_end") VALUES (%s, %s, %s, %s) RETURNING "rid"'''

	assert(ctx.run_start.tzinfo == datetime.timezone.utc)
	assert(ctx.run_end.tzinfo == datetime.timezone.utc)

	with ctx.db.cursor() as c:
		c.execute(q, (ctx.conf['metalink'], ctx.conf['baseurl'],
			  ctx.run_start, ctx.run_end, ))
		return c.fetchone()[0]

def insert_into_filemeta (ctx: Context, run: int):
	q = '''INSERT INTO "filemeta" ("run", "file", "size", "hash") VALUES (%s, %s, %s, %s)'''

	with ctx.db.cursor() as c:
		for file, fml in ctx.collated.items():
			for fm in fml:
				hash = " ".join(fm.hashmap.values())
				c.execute(q, (run, file, fm.size, hash, ))

def insert_into_files (ctx: Context, run: int):
	q = '''INSERT INTO "files"
		("run", "name", "resolved", "status", "content_len", "hash", "transfer_time", "transfer_size")
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s)'''

	with ctx.db.cursor() as c:
		for file, fo in ctx.objmap.items():
			hash = " ".join(fo.hashmap.values())
			c.execute(q, (run, file, fo.resolved, fo.status,
				  fo.content_len, hash, fo.transfer_time, fo.size, ))

def do_final_inserts (ctx: Context):
	try:
		run = insert_into_run(ctx)
		insert_into_filemeta(ctx, run)
		insert_into_files(ctx, run)
	except:
		ctx.db.rollback()
		raise
	else:
		ctx.db.commit()

def goget (m: dict, path: Iterable[str], d):
	assert(len(path) > 0)

	for cur in path[:-1]:
		m = m.get(cur, {})

	return m.get(path[-1], d)

def do_trunc (ctx: Context):
	q_bgp = '''DELETE FROM "bgp" WHERE "ts" < %s'''
	q_runs = '''DELETE FROM "runs" WHERE "run_end" < %s'''

	now = datetime.datetime.now(datetime.timezone.utc)
	bgp_cutoff_secs = goget(ctx.conf, ['retain', 'bgp'], DEFAULT_BGP_RETAIN)
	bgp_cutoff_ts = now - datetime.timedelta(seconds=bgp_cutoff_secs)

	runs_cutoff_secs = goget(ctx.conf, ['retain', 'run'], DEFAULT_RUN_RETAIN)
	runs_cutoff_ts = now - datetime.timedelta(seconds=runs_cutoff_secs)

	with ctx.db.cursor() as c:
		c.execute(q_bgp, (bgp_cutoff_ts,))
		c.execute(q_runs, (runs_cutoff_ts,))

def do_test (conf: dict[str, Any]):
	with Context(conf) as ctx:
		ctx.run_start = datetime.datetime.now(datetime.timezone.utc)
		collect_on_repodata(ctx)
		ctx.run_end = datetime.datetime.now(datetime.timezone.utc)

		do_trunc(ctx)
		resolve_hosts(ctx)
		do_final_inserts(ctx)
