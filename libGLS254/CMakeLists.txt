
#project(libGLS254)
 
#############################################
#                 Link Miracl               #
#############################################
set(Miracl1_Dirs "${CMAKE_CURRENT_SOURCE_DIR}/../externals")

set(Miracl1_Lib_Dirs "${Miracl1_Dirs}/Miracl/src/")
set(Miracl1_Include_Dirs "${Miracl1_Dirs}/miracl_lib/")

find_library(
MIRACL1_LIB 
NAMES miracl miracl.a
HINTS "${Miracl1_Include_Dirs}")

# if we cant fint it, throw an error
if(NOT MIRACL1_LIB)
    message(FATAL_ERROR "Failed to find miracl at " ${Miracl1_Include_Dirs})
endif()
message(STATUS "MIRACL1_LIB:  ${MIRACL1_LIB}")

	
#############################################
#              Build libGLS254                #
#############################################

file(GLOB_RECURSE SRCS *.cpp)
 

add_library(libGLS254 ${SRCS})

target_include_directories(libGLS254 PUBLIC  ${Miracl1_Include_Dirs}) 

target_link_libraries(libGLS254 ${MIRACL1_LIB} )
