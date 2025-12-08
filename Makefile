.PHONY: rebuild clean all

all: result.csv

result.csv:
	python -m mirrorwatch > result.csv.tmp
	mv result.csv.tmp result.csv

clean:
	rm -f *.tmp result.csv

rebuild: clean all # TODO
