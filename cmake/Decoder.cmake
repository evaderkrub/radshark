# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dave Robins

set(VSPYSHARK_SERVER_DIST "${VSPYSHARK_WIRESPY_DIR}/dist/wirespy" CACHE PATH "Staged wirespy decoder and runtime files")
function(vspyshark_stage_decoder target)
    if(EXISTS "${VSPYSHARK_SERVER_DIST}/wirespy_server.exe" OR EXISTS "${VSPYSHARK_SERVER_DIST}/wirespy_server")
        add_custom_command(TARGET ${target} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${VSPYSHARK_SERVER_DIST}" "$<TARGET_FILE_DIR:${target}>/wirespy")
    else()
        message(STATUS "VSpy Shark: set VSPYSHARK_SERVER_DIST or WIRESPY_SERVER to provide the separate decoder")
    endif()
endfunction()
