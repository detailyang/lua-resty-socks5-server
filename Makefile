.PHONY: test
test:
	@WORKDIR=$(shell pwd) /usr/bin/prove
