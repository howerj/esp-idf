idf_component_register(SRCS "src/pickle.c" INCLUDE_DIRS "include")
target_compile_definitions(${COMPONENT_LIB} PUBLIC "-DPICKLE_VERSION=0x040104ul" "-DPICKLE_MAX_RECURSION=16")
