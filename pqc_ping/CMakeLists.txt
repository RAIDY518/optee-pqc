project (optee_example_pqc_ping C)

set (KEM_DIR ta/pqclean/kem)
set (COMM_DIR ta/pqclean/common)

set (SRC
    host/main.c
    host/randombytes_host.c
    ${KEM_DIR}/kem.c
    ${KEM_DIR}/indcpa.c
    ${KEM_DIR}/poly.c
    ${KEM_DIR}/polyvec.c
    ${KEM_DIR}/ntt.c
    ${KEM_DIR}/cbd.c
    ${KEM_DIR}/reduce.c
    ${KEM_DIR}/symmetric-shake.c
    ${KEM_DIR}/verify.c
    ${COMM_DIR}/fips202.c
)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include
			   PRIVATE host/include
			   PRIVATE ${KEM_DIR}
			   PRIVATE ${COMM_DIR})

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (PROGRAMS $<TARGET_FILE:${PROJECT_NAME}> DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME pqc_ping)
