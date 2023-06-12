option(SUBMODULE_CHECK "Enables checking that vendored submodules are up to date" ON)

function(check_submodule relative_path)
    execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE localHead)
    execute_process(COMMAND git rev-parse "HEAD:external/${relative_path}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE checkedHead)
    string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
    if (upToDate)
        message(STATUS "Submodule 'external/${relative_path}' is up-to-date")
    elseif(SUBMODULE_CHECK)
        message(FATAL_ERROR "Submodule 'external/${relative_path}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
    else()
        message(WARNING "Submodule 'external/${relative_path}' is not up-to-date")
    endif()

    # Extra arguments check nested submodules
    foreach(submod ${ARGN})
        execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/${submod} OUTPUT_VARIABLE localHead)
        execute_process(COMMAND git rev-parse "HEAD:${submod}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE checkedHead)
        string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
        if (NOT upToDate)
            if(SUBMODULE_CHECK)
                message(FATAL_ERROR "Nested submodule '${relative_path}/${submod}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
            else()
                message(WARNING "Nested submodule '${relative_path}/${submod}' is not up-to-date")
            endif()
        endif()
    endforeach()
endfunction ()
