add_executable(analyzer main.cpp)

if(WIN)
  target_sources(analyzer PRIVATE resource.rc)
endif()

sogen_assign_source_group(main.cpp)

target_link_libraries(analyzer PRIVATE windows-analyzer linux-analyzer)

# whp-emulator.dll depends on a WinHvPlatform export missing on Win10 hosts without Hyper-V.
# We use the icicle backend, never WHP, so delay-load it: the DLL is only loaded if the WHP
# backend is actually selected (never), letting analyzer.exe start on any Win10 host.
if(MSVC)
  target_link_options(analyzer PRIVATE /DELAYLOAD:whp-emulator.dll)
  target_link_libraries(analyzer PRIVATE delayimp)
endif()

set_property(GLOBAL PROPERTY VS_STARTUP_PROJECT analyzer)

sogen_strip_target(analyzer)

add_test(NAME analyzer-test
         COMMAND "${PYTHON3_EXE}" "${CMAKE_CURRENT_LIST_DIR}/../windows-analyzer/test.py"
         WORKING_DIRECTORY "$<TARGET_FILE_DIR:analyzer>")
