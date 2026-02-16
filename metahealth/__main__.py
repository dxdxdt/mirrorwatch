from datetime import timedelta
import random
import sys
import time

from metahealth import *

import json5
import psycopg2

with open(sys.argv[1]) as f:
	OPTS = json5.load(f)
INTERVAL = float(OPTS.get('interval', 60.0))

random.seed()

with psycopg2.connect(**OPTS['db']) as db:
	while True:
		start = time.monotonic_ns()
		code, len = pull_url(OPTS['url'])
		end = time.monotonic_ns()
		runtime_us = (end - start) // 1000

		_, ts = do_insert(db, code, len, runtime_us)
		bfr = ts - timedelta(days = 360)
		do_trunc(db, bfr)
		db.commit()

		jitter = 1.0 - (random.random() * 2.0)
		# sys.stderr.write('%.3f\n' % (jitter, ))
		delay = INTERVAL + jitter
		if delay > 0.0:
			time.sleep(delay)
