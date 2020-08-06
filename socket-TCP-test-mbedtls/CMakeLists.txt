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

add_custom_target(libs COMMAND make WORKING_DIRECTORY host/libs/libmbedtls)
add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE host/src
			   PRIVATE host/certs
			   PRIVATE host/credentials
			   PUBLIC host/libs/libmbedtls/include/
			)

target_link_libraries (${PROJECT_NAME}
				PRIVATE teec
				libs/libmbedtls.a
				libs/libmbedx509.a
				libs/libmbedcrypto.a)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
