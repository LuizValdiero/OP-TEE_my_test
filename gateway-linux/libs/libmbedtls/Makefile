PREFIX=mbedtls_
CROSS_COMPILE := /home/luiz/Documentos/LISHA/trustzone/qemuv7/toolchains/aarch32/bin/arm-linux-gnueabihf-
.SILENT:

.PHONY: lib clean

lib:
	@$(MAKE) -C library CC=$(CROSS_COMPILE)gcc
	cp ./library/libmbedcrypto.a ../
	cp ./library/libmbedtls.a ../
	cp ./library/libmbedx509.a ../

clean:
	$(MAKE) -C library clean

