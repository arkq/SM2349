CC = gcc
CFLAGS = -I./miracl/include
LIBS = miracl.a

.PHONY: all
all: SM2enc SM2key SM2sv SM3 SM4 ZUC

.PHONY: clean
clean:
	$(RM) SM2enc SM2key SM2sv SM3 SM4 ZUC

SM2enc: src/SM2_ENC.o src/SM3.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

SM2key: src/SM2_KEY_EX.o src/SM3.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

SM2sv: src/SM2_sv.o src/SM3.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

SM3: src/SM3_m.o src/SM3.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

SM4: src/SM4.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

ZUC: src/ZUC.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

## BEGIN
## Build MIRACL library for x64 Linux platform

MIRACL := mrcore.o mrarth0.o mrarth1.o mrarth2.o mralloc.o mrsmall.o \
	mrio1.o mrio2.o mrgcd.o mrjack.o mrxgcd.o mrarth3.o mrbits.o mrrand.o \
	mrprime.o mrcrt.o mrscrt.o mrmonty.o mrpower.o mrsroot.o mrcurve.o mrfast.o \
	mrshs.o mrshs256.o mrshs512.o mrsha3.o mrfpe.o mraes.o mrgcm.o mrlucas.o \
	mrzzn2.o mrzzn2b.o mrzzn3.o mrzzn4.o mrecn2.o mrstrong.o mrbrick.o \
	mrebrick.o mrec2m.o mrgf2m.o mrflash.o mrfrnd.o mrdouble.o mrround.o \
	mrbuild.o mrflsh1.o mrpi.o mrflsh2.o mrflsh3.o mrflsh4.o mrmuldv_.o
.PHONY: miracl/include/mirdef.h
miracl/include/mirdef.h: miracl/include/mirdef.h64
	cp miracl/include/mirdef.h64 miracl/include/mirdef.h
miracl/source/mrmuldv_.c: miracl/source/mrmuldv.g64
	cp miracl/source/mrmuldv.g64 miracl/source/mrmuldv_.c
miracl/%.o: miracl/%.c miracl/include/mirdef.h
	$(CC) -c -o $@ $< $(CFLAGS)
miracl.a: $(foreach src,$(MIRACL),miracl/source/$(src))
	$(AR) -rcs $@ $?

## END
