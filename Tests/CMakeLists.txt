
#project(libTests)

file(GLOB_RECURSE SRCS *.cpp)
add_library(libTests STATIC ${SRCS})

target_include_directories(libTests PUBLIC ${CMAKE_SOURCE_DIR}) 
target_link_libraries(libTests libPSI)
