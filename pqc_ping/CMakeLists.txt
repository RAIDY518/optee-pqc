project (optee_example_pqc_ping C)

set (KEM_DIR ta/pqclean/kem)
set (SIG_DIR ta/pqclean/sig)
set (COMM_DIR ta/pqclean/common)

# Common sources (fips202/SHAKE) — shared between KEM and SIG, no collision.
add_library(pqc_common OBJECT
    ${COMM_DIR}/fips202.c
)
target_include_directories(pqc_common PRIVATE ${COMM_DIR} host/include)

# ML-KEM-512 sources — isolated include path (KEM_DIR only, never SIG_DIR).
add_library(pqc_kem OBJECT
    ${KEM_DIR}/kem.c
    ${KEM_DIR}/indcpa.c
    ${KEM_DIR}/poly.c
    ${KEM_DIR}/polyvec.c
    ${KEM_DIR}/ntt.c
    ${KEM_DIR}/cbd.c
    ${KEM_DIR}/reduce.c
    ${KEM_DIR}/symmetric-shake.c
    ${KEM_DIR}/verify.c
)
target_include_directories(pqc_kem PRIVATE ${KEM_DIR} ${COMM_DIR} host/include)

# ML-DSA-44 sources — isolated include path (SIG_DIR only, never KEM_DIR).
add_library(pqc_sig OBJECT
    ${SIG_DIR}/sign.c
    ${SIG_DIR}/packing.c
    ${SIG_DIR}/poly.c
    ${SIG_DIR}/polyvec.c
    ${SIG_DIR}/ntt.c
    ${SIG_DIR}/reduce.c
    ${SIG_DIR}/rounding.c
    ${SIG_DIR}/symmetric-shake.c
)
target_include_directories(pqc_sig PRIVATE ${SIG_DIR} ${COMM_DIR} host/include)

# Host application
add_executable (${PROJECT_NAME}
    host/main.c
    host/randombytes_host.c
    $<TARGET_OBJECTS:pqc_kem>
    $<TARGET_OBJECTS:pqc_sig>
    $<TARGET_OBJECTS:pqc_common>
)

target_include_directories(${PROJECT_NAME}
    PRIVATE ta/include
    PRIVATE include
    PRIVATE host/include
    PRIVATE ${KEM_DIR}
    PRIVATE ${SIG_DIR}
    PRIVATE ${COMM_DIR}
)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (PROGRAMS $<TARGET_FILE:${PROJECT_NAME}> DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME pqc_ping)
