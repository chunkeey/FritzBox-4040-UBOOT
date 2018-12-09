
.PHONY: all clean

all: lzma2eva tichksum
clean:
	rm -f lzma2eva tichksum

lzma2eva: lzma2eva.c
	$(CC) -o $@ $<

tichksum: tichksum.c
	$(CC) -o $@ $<
