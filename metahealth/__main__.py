import sys
import random
import traceback

import json5

import metahealth

random.seed()

succ = 0
fail = 0

# TODO start delay w/ jitter

for path in sys.argv[1:]:
	try:
		with open(path) as f:
			conf = json5.load(f)
			f.close()
			metahealth.do_test(conf)
			succ += 1
	except Exception as e:
		traceback.print_exception(e)
		fail += 1

if fail > 0:
	if succ > 0: sys.exit(3)
	else: sys.exit(1)
else:
	if succ == 0: sys.exit(2)
	else: sys.exit(0)
