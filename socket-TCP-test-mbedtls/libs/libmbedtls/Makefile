PREFIX=mbedtls_

.SILENT:

.PHONY: lib clean

lib:
	@$(MAKE) -C library
	cp ./library/libmbedcrypto.a ../
	cp ./library/libmbedtls.a ../
	cp ./library/libmbedx509.a ../

clean:
	$(MAKE) -C library clean

