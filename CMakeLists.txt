cmake_minimum_required(VERSION 3.5)
project(randsteg)
set(CMAKE_C_STANDARD 11)

add_executable(randsteg src/stegno.c src/sha_with_salt.c src/aes.c src/log_tools.c src/png_tools.c src/hash_table.c)
target_compile_options(randsteg PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(randsteg PRIVATE -lm -lcrypto -lm -lpng)

# Packaging
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES ${CMAKE_BINARY_DIR} /\\..*$)
set(CPACK_VERBATIM_VARIABLES YES)
include(CPack)
