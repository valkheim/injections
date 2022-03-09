file(GLOB_RECURSE sources "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_library(dll_sample_injectee SHARED ${sources})

find_program(POWERSHELL_PATH NAMES powershell)
set(infos_dir "${CMAKE_CURRENT_LIST_DIR}/infos/${CMAKE_GENERATOR_PLATFORM}")
set(scripts_dir "${CMAKE_CURRENT_LIST_DIR}/scripts")

add_custom_command(TARGET dll_sample_injectee POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${infos_dir}
    COMMAND ${POWERSHELL_PATH} "${scripts_dir}/post_build.ps1" -Path "$<TARGET_FILE:dll_sample_injectee>" -Out "${infos_dir}"
)
