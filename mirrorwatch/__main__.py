import csv
import os
import socket
import sys
import requests

from mirrorwatch import *


ARGV0 = 'mirrorwatch'
MIRRORLIST_URL = "https://mirrormanager.fedoraproject.org/mirrors"
MIRRORLIST_PULL_PAGESIZE = 200

def perrmsg (msg: str):
	sys.stderr.write(('%s: %s' + os.linesep) % (ARGV0, msg))

def parse_mirrorpage (doc: str) -> list[MirrorInfo]:
	pp = PageParser()
	pp.feed(doc)
	return pp.result

def pull_mirrors (url: str, pagesize: int = MIRRORLIST_PULL_PAGESIZE) -> tuple[list[MirrorInfo], int, int]:
	page = 1
	ret = list[MirrorInfo]()
	dupset = set[str]()
	cnt = 0
	dup_cnt = 0

	while True:
		payload = {
			"page_size": str(pagesize),
			"page_number": str(page),
		}
		with requests.get(url, params = payload) as req:
			perrmsg('pulled %s' % (req.url,))

			r = parse_mirrorpage(req.text)
			# remove dupes
			for mi in r:
				for h in list(mi.mirror_host):
					if h in dupset:
						mi.mirror_host.remove(h)
						dup_cnt += 1
					else:
						dupset.add(h)
						cnt += 1

				if mi.mirror_host:
					ret.append(mi)

			if len(r) < pagesize:
				break
		page += 1

	return (ret, cnt, dup_cnt,)

def pull_hostaddr (hostname: Iterator[str]) -> list[HostNetInfo]:
	ret = []

	for h in hostname:
		perrmsg('resolving %s ...' % (str(h),))
		try:
			s = set[str](p[4][0] for p in socket.getaddrinfo(h, None))
			for addr in s:
				hni = HostNetInfo()
				hni.host = hostname
				hni.ipaddr = addr
				ret.append(hni)
		except socket.gaierror as e:
			perrmsg('warning: failed to resolve %s (%s)' % (str(h), str(e),))

	return ret

"""
def load_radb (file: io.TextIOBase, types: set[str]) -> list[dict[str, list[str]]]:
	ret = list[dict[str, list[str]]]()
	cur = dict[str, list[str]]()
	skip_flag = False

	for line in file:
		line = line.strip()
		if line.startswith('#'): continue
		if line:
			if skip_flag: continue

			sep = line.find(':')
			if sep < 0: continue
			k = line[:sep]
			v = line[sep + 1:].lstrip()

			# the first line
			# check the object type to filter it
			if (types is not None) and (not cur) and (k not in types):
				skip_flag = True
				continue
			e = cur.setdefault(k, list[str]())
			e.append(v)
		else:
			skip_flag = False
			if cur:
				ret.append(cur)
				cur = dict[str, list[str]]()

	return ret
"""

"""
def build_tree (db: Iterator[dict[str, list[str]]]) -> radix.Radix:
	ret = radix.Radix()

	for obj in db:
		prefix = obj.get('route') or obj.get('route6')
		if not prefix: continue
		assert '/' in prefix[0]
		rnode = ret.add(prefix[0])
		rnode.data['obj'] = obj

	return ret
"""

"""
def find_route_origin (rib: radix.Radix, addr: str) -> tuple[str, str]:
	found = rib.search_best(addr)
	if found:
		obj = found.data['obj']
		return (obj['origin'][0], obj.get('descr', [''])[0],)
	return ('', '',)
"""


""" main starts here"""

"""
# load radb from stdin
perrmsg('warning: this program requires a large amount of ram (> 2 GB)')
perrmsg('loading radb from stdin ...')
radb = load_radb(sys.stdin, {'route', 'route6',})
perrmsg('%d entries loaded' % (len(radb),))

# index it
perrmsg('indexing radb ...')
rib = build_tree(radb)
perrmsg('%d route entries indexed' % (len(rib.nodes()),))
"""

# pull mirror list from the web pages
perrmsg('pulling mirror list pages ...')
mirrors, cnt, dupes = pull_mirrors(MIRRORLIST_URL)
perrmsg('pulled %d mirrors (%d dupes removed)' % (cnt, dupes))

# pull A and AAAA records
perrmsg('resolving A and AAAA ...')
cnt = 0
for m in mirrors:
	m.hnlist = pull_hostaddr(m.mirror_host)
	cnt += len(m.hnlist)
perrmsg('resolved %d host records' % (cnt,))

# query route objects of the addresses
with WhoisQueryConnection() as wqc:
	# make a flat list for query pipelining
	wqc.query_routes([ h for m in mirrors for h in m.hnlist ])

# output csv
w = csv.writer(sys.stdout)
for m in mirrors:
	for h in m.hnlist:
		w.writerow((
			m.country,
			', '.join(m.mirror_host),
			h.ipaddr,
			h.route,
			h.origin,
			h.descr))
sys.stdout.flush()
