macro(link_openssl TARGET_NAME)
  if(IS_LINUX)
    set(OPENSSL_PATH "/usr/local/opt/openssl@3.2.0")
    include_directories(${OPENSSL_PATH}/include)
    target_link_libraries(${TARGET_NAME} PUBLIC ${OPENSSL_PATH}/lib64/libcrypto.a)
  endif()

  if(IS_MACOS)
    include_directories("/opt/homebrew/opt/openssl/include")
    target_link_libraries(${TARGET_NAME} PUBLIC
                          "/opt/homebrew/opt/openssl/lib/libcrypto.a")
  endif()
endmacro(link_openssl)
