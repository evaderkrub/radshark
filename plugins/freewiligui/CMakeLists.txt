# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dave Robins

if(NOT TARGET freewiligui::sdk)
    set(FREEWILIGUI_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../../FreeWilli/freewiligui-sdk" CACHE PATH "Standalone FreeWili GUI SDK checkout")
    if(EXISTS "${FREEWILIGUI_SDK_DIR}/CMakeLists.txt")
        set(FREEWILIGUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(FREEWILIGUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        add_subdirectory("${FREEWILIGUI_SDK_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/sdk")
    else()
        find_package(freewiligui 0.1 CONFIG REQUIRED)
    endif()
endif()
set(FREEWILIGUI_IMGUI_TARGET "${VSPYSHARK_IMGUI_TARGET}")
set(FREEWILIGUI_IMPLOT_TARGET "${VSPYSHARK_IMGUI_TARGET}")
set(FREEWILIGUI_IMGUI_TEST_ENGINE "${VSPYSHARK_TEST_ENGINE}")
freewiligui_add_plugin(fwgui_vspyshark ID com.intrepidcs.vspyshark SYMBOL fwgui_vspyshark SOURCES plugin.cpp
    PLUGIN_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins")
target_link_libraries(fwgui_vspyshark PRIVATE vspyshark_gui)
vspyshark_stage_decoder(fwgui_vspyshark)
