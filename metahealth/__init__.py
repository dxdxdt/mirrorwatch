import datetime

import requests


def do_insert (db, code: int, len: int, runtime_us: int | None) -> tuple[int, datetime.datetime]:
	# clamp runtime_us
	if runtime_us is not None:
		if runtime_us < 0:
			raise ValueError("""runtime_us""")
		elif runtime_us > 2147483647:
			runtime_us = 2147483647

	with db.cursor() as c:
		c.execute(
			'''INSERT INTO "url-http-code" ( "code", "len", "runtime_us" )
			VALUES (%s, %s, %s)
			RETURNING rid, ts''',
			( code, len, runtime_us, ))
		ret = c.fetchone()

		return ( ret[0], ret[1], )

def do_trunc (db, bfr: datetime.datetime):
	with db.cursor() as c:
		c.execute('''DELETE FROM "url-http-code" WHERE "ts" < %s''', (bfr,))

def pull_url (url) -> tuple[int, int]:
	with requests.get(url, headers = {
				'User-Agent': 'libdnf (Get 69; stuffed; tosser.shitbox)',
				# 'Accept': 'application/xml'
			}) as r:
		return ( r.status_code, len(r.text), )
