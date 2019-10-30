CC = gcc
CFLAGS =
LIBS = miracl.a

all: SM2enc SM2key SM2sv SM3 SM4 ZUC

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
