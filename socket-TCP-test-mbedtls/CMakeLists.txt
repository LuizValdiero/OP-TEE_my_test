project (socket-TCP-test-mbedtls C)

set (SRC
	src/main.c
	src/crypto.c
	src/connections_handler.c
	src/data_structure/record.c
	src/data_structure/serie.c
	src/data_handler.c
	src/http_handler.c
	src/my_post.c
	src/serial_package.c
	src/tls_handler.c
	src/utils/data_version_handler.c
	src/utils/double_format_handler.c)

add_custom_target(libs COMMAND make WORKING_DIRECTORY libs/libmbedtls)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories (${PROJECT_NAME}
			   PRIVATE src
			   PRIVATE certs
			   PRIVATE credentials
			   PUBLIC libs/libmbedtls/include/
			   PUBLIC libs)

target_link_libraries(${PROJECT_NAME} PRIVATE
				-L/home/luiz/Documentos/LISHA/trustzone/my_package/socket-TCP-test-mbedtls/libs
				teec
				libmbedtls.a
				libmbedx509.a
				libmbedcrypto.a)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
