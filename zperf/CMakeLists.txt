# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(zperf)


if(CONFIG_USB_DEVICE_NETWORK_MY_ECM)
    message(STATUS "*** MY_ECM active ***")
    
    target_include_directories(app PRIVATE
        # IP headers
        ${ZEPHYR_BASE}/subsys/net/ip
    )

    target_sources(app PRIVATE
        src/netusb/function_ecm.c
    )
endif()


target_sources(app PRIVATE
    src/main.c
)
