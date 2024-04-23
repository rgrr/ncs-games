/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Zperf sample.
 */

/**
 * Host setup etc
 * ==============
 *
 * sudo systemctl restart networking.service
 * sudo ip addr add 2001:db8::2/64 dev enx00005e005301
 *
 *
 * /etc/network/interfaces
 * -----------------------
 *   allow-hotplug enx00005e005301
 *   iface enx00005e005301 inet static
 *       address 192.168.2.2
 *       netmask 255.255.255.0
 *   iface enx00005e005301 inet6 static
 *       address 2001:db8::2
 *       netmask 64
 *
 * DHCPv4 server sets unfortunately the default route?
 *
 *
 * Testing
 * -------
 * iperf IPv6:
 *     for MSS in 10 100 800 1450; do iperf -c 2001:db8::1 -e -i 1 -M $MSS -l 8192 -P 1; sleep 2; done
 *     for MSS in 10 20 40 80 160 320 640 1000 1100 1200 1300 1400 1500; do iperf -c 2001:db8::1 -e -i 1 -M $MSS -l 8192 -P 1; sleep 2; done
 *
 * iperf UDP does only work with IPv4!
 *     for MSS in 10 20 40 80 160 320 640 1000 1100 1200 1300 1400 1500; do iperf -c 192.168.2.1 -e -i 1 -M $MSS -l 8192 -P 1 -u; sleep 2; done
 *
 * Other tests:
 *     iperf -c 192.168.2.1 -e -i 1 -M 8000 -l 125 -P 1 -b 1000
 *     for MSS in {100..512}; do iperf -c 192.168.2.1 -e -i 1 -M $MSS -l 8192 -P 1; sleep 2; done
 *
 * Telnet:
 *     telnet 2001:db8::1
 *
 * SystemView tracing:
 *     cp $ZEPHYR_BASE/subsys/tracing/sysview/SYSVIEW_Zephyr.txt /opt/SEGGER/SystemView_V352a/Description
 *
 *     this did not work:
 *         cp $ZEPHYR_BASE/subsys/tracing/sysview/SYSVIEW_Zephyr.txt ~/.config/SEGGER/
 *
 */

#include <zephyr/logging/log.h>
#include <zephyr/net/dhcpv4_server.h>
#include <zephyr/net/net_config.h>
#include <zephyr/net/zperf.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/usbd.h>

#ifdef CONFIG_NET_LOOPBACK_SIMULATE_PACKET_DROP
    #include <zephyr/net/loopback.h>
#endif

#if defined(CONFIG_USB_DEVICE_STACK_NEXT)
    #include <sample_usbd.h>
#endif


LOG_MODULE_REGISTER(zperf, LOG_LEVEL_DBG);


#define DHCPV4_POOL_START "192.168.2.20"



#if defined(CONFIG_USB_DEVICE_STACK_NEXT)
static int enable_usb_device_next(void)
{
    struct usbd_contex *sample_usbd = sample_usbd_init_device(NULL);

    if (sample_usbd == NULL) {
        printk("Failed to initialize USB device");
        return -ENODEV;
    }

    return usbd_enable(sample_usbd);
}
#endif /* CONFIG_USB_DEVICE_STACK_NEXT */



void my_zperf_callback(enum zperf_status status,
                       struct zperf_results *result,
                       void *user_data)
/**
 * Print out some statistics.
 *
 * \note
 *    works only with TCP
 */
{
    if (status == ZPERF_SESSION_STARTED)
    {
        LOG_INF("------------------------------------------------");
        LOG_INF("zperf session started...");
    }
    else if (status == ZPERF_SESSION_FINISHED)
    {
        LOG_INF("...finished");

        if (result != NULL)
        {
#if 0
            printk("total:                  %d bytes\n", (int)result->total_len);
            printk("packet_size:            %d\n", result->packet_size);
            printk("duration:               %dms\n", (int)(result->time_in_us / 1000));
            printk("jitter_in_us:           %dus\n", result->jitter_in_us);
            printk("client_time_in_us:      %dus\n", (int)result->client_time_in_us);

            printk("nb_packets_sent:        %d\n", result->nb_packets_sent);
            printk("nb_packets_rcvd:        %d\n", result->nb_packets_rcvd);
            printk("nb_packets_lost:        %d\n", result->nb_packets_lost);
            printk("nb_packets_outorder:    %d\n", result->nb_packets_outorder);
            printk("nb_packets_errors:      %d\n", result->nb_packets_errors);
#else
            LOG_INF("total:                  %d bytes", (int)result->total_len);
            LOG_INF("duration:               %dms", (int)(result->time_in_us / 1000));
            LOG_INF("throughput:             %d bytes/s", (int)((100*result->total_len) / (result->time_in_us / 10000)));
            LOG_INF("                        %d bit/s", (int)((100*result->total_len) / (result->time_in_us / 80000)));
#endif
        }
        LOG_INF("================================================");
    }
    else
    {
        LOG_ERR("zperf error: %d\n", status);
    }
}   // zperf_callback



#if CONFIG_NET_DHCPV4_SERVER
static void configure_dhcp_server(void)
/**
 * Start DHCPv4 server
 *
 * TODO it seems that the stack is too small
 */
{
    struct net_if *iface;
    struct in_addr pool_start;
    int ret;

    iface = net_if_get_first_up();
    if ( !iface)
    {
        LOG_ERR("Failed to get network interface");
        return;
    }

    if (net_addr_pton(AF_INET, DHCPV4_POOL_START, &pool_start.s_addr))
    {
        LOG_ERR("Invalid address: %s", DHCPV4_POOL_START);
        return;
    }

    ret = net_dhcpv4_server_start(iface, &pool_start);
    if (ret == -EALREADY)
    {
        LOG_ERR("DHCPv4 server already running on interface");
    }
    else if (ret < 0)
    {
        LOG_ERR("DHCPv4 server failed to start and returned %d error", ret);
    }
    else
    {
        LOG_INF("DHCPv4 server started and pool address starts from %s", DHCPV4_POOL_START);
    }
}   // configure_dhcp_server
#endif



int main(void)
{
#if defined(CONFIG_USB_DEVICE_STACK) || defined(CONFIG_USB_DEVICE_STACK_NEXT)
    int ret;

#if defined(CONFIG_USB_DEVICE_STACK)
    ret = usb_enable(NULL);
#endif
#if defined(CONFIG_USB_DEVICE_STACK_NEXT)
    ret = enable_usb_device_next();
#endif
    if (ret != 0) {
        printk("usb enable error %d\n", ret);
    }

    (void)net_config_init_app(NULL, "Initializing network");
#endif /* CONFIG_USB_DEVICE_STACK */

#ifdef CONFIG_NET_LOOPBACK_SIMULATE_PACKET_DROP
    loopback_set_packet_drop_ratio(1);
#endif

    //
    // automatically start TCP/UDP server
    //
    k_msleep(500);
    {
        static const struct zperf_download_params param = { .port = 5001 };

        zperf_tcp_download( &param, my_zperf_callback, NULL);
        zperf_udp_download( &param, my_zperf_callback, NULL);   // just with IPv4?  And no callback?
    }

    return 0;
}
