

add_custom_command(
        OUTPUT libpistache.a
        COMMAND sh -c '[ -e libpistache.a ] || bash build_pistache.sh'
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(
    pistache-build
    DEPENDS libpistache.a
)