project (optee_example_pqc_ping C)

set (SRC host/main.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (PROGRAMS $<TARGET_FILE:${PROJECT_NAME}> DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME pqc_ping)
