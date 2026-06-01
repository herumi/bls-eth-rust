.PHONY: clean test

clean:
	cargo clean
	$(MAKE) -C bls -f Makefile.onelib clean

test:
	cargo test
