project (socket-TCP-test-mbedtls C)

add_custom_command(OUTPUT ./host/socket-TCP-test-mbedtls COMMAND make
                   DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/
)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
