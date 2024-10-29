set(serialize_sources
  block_blob.cpp)

set(serialize_headers)

monero_add_minimal_executable(serialize-tests
  ${serialize_sources}
  ${serialize_headers})
target_link_libraries(serialize-tests
  PRIVATE
    cryptonote_basic
    ${EXTRA_LIBRARIES})
set_property(TARGET serialize-tests
  PROPERTY
    FOLDER "tests")
