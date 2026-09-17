# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dave Robins

include(FetchContent)
if(NOT TARGET nlohmann_json::nlohmann_json)
    FetchContent_Declare(nlohmann_json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.11.3 GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(nlohmann_json)
endif()
if(NOT TARGET wirespy_client)
    if(NOT EXISTS "${RADSHARK_WIRESPY_DIR}/src/client/CMakeLists.txt")
        message(FATAL_ERROR "Set RADSHARK_WIRESPY_DIR to the independent wirespy repository")
    endif()
    add_subdirectory("${RADSHARK_WIRESPY_DIR}/src/client" "${CMAKE_CURRENT_BINARY_DIR}/wirespy_client")
endif()
if(NOT RADSHARK_IMGUI_TARGET)
    FetchContent_Declare(imgui GIT_REPOSITORY https://github.com/ocornut/imgui.git GIT_TAG v1.92.8-docking GIT_SHALLOW TRUE)
    FetchContent_Declare(implot GIT_REPOSITORY https://github.com/epezent/implot.git GIT_TAG v1.0 GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(imgui implot)
    add_library(shark_imgui STATIC "${imgui_SOURCE_DIR}/imgui.cpp" "${imgui_SOURCE_DIR}/imgui_draw.cpp" "${imgui_SOURCE_DIR}/imgui_demo.cpp"
        "${imgui_SOURCE_DIR}/imgui_tables.cpp" "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
        "${implot_SOURCE_DIR}/implot.cpp" "${implot_SOURCE_DIR}/implot_items.cpp")
    target_include_directories(shark_imgui PUBLIC "${imgui_SOURCE_DIR}" "${implot_SOURCE_DIR}")
    if(RADSHARK_TEST_ENGINE)
        target_compile_definitions(shark_imgui PUBLIC IMGUI_ENABLE_TEST_ENGINE)
    endif()
    set(RADSHARK_IMGUI_TARGET shark_imgui)
elseif(NOT TARGET "${RADSHARK_IMGUI_TARGET}")
    message(FATAL_ERROR "RADSHARK_IMGUI_TARGET must name an existing target")
endif()
