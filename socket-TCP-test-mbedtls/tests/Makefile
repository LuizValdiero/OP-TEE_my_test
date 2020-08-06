CC := gcc


.PHONY: all

all: mount_request



.PHONY: mount_request

SRCS_MOUNT_REQUEST =
SRCS_MOUNT_REQUEST += ../src/my_post.c
SRCS_MOUNT_REQUEST += ../src/data_handler.c
SRCS_MOUNT_REQUEST += ../src/http_handler.c
SRCS_MOUNT_REQUEST += test_mount_request/test_mount_request.c

mount_request: $(SRCS_MOUNT_REQUEST)
	@echo "compile $@"
	@$(CC) $(FLAGS) $^ -o $@


.PHONY: double_format

SRCS_DOUBLE_FORMAT =
SRCS_DOUBLE_FORMAT += ../src/utils/double_format_handler.c
SRCS_DOUBLE_FORMAT += test_double_format/test_double_format.c

double_format: $(SRCS_DOUBLE_FORMAT)
	@echo "compile $@"
	@$(CC) $(FLAGS) $^ -o $@

.PHONY: clean
clean:
	@echo "clean"
	@rm -rf *.o *~ mount_request double_format
