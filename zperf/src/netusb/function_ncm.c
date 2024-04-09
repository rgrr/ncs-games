/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Specification
 * -------------
 * NCM spec can be obtained here: https://www.usb.org/document-library/network-control-model-devices-specification-v10-and-errata-and-adopters-agreement
 *
 * Small Glossary (from the spec)
 * --------------
 * Datagram - A collection of bytes forming a single item of information, passed as a unit from source to destination.
 * NCM      - Network Control Model
 * NDP      - NCM Datagram Pointer: NTB structure that delineates Datagrams (typically Ethernet frames) within an NTB
 * NTB      - NCM Transfer Block: a data structure for efficient USB encapsulation of one or more datagrams
 *            Each NTB is designed to be a single USB transfer
 * NTH      - NTB Header: a data structure at the front of each NTB, which provides the information needed to validate
 *            the NTB and begin decoding
 *
 * Some explanations
 * -----------------
 * - rhport        is the USB port of the device, in most cases "0"
 * - itf_data_alt  if != 0 -> data xmit/recv are allowed (see spec)
 * - ep_in         IN endpoints take data from the device intended to go in to the host (the device transmits)
 * - ep_out        OUT endpoints send data out of the host to the device (the device receives)
 */


#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(usb_ncm, CONFIG_USB_DEVICE_NETWORK_LOG_LEVEL);

/* Enable verbose debug printing extra hexdumps */
#define VERBOSE_DEBUG   0

#include <zephyr/net/net_pkt.h>
#include <zephyr/net/ethernet.h>
#include "net_private.h"

#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_cdc.h>
#include <usb_descriptor.h>

#include "netusb.h"

#define USB_CDC_ECM_REQ_TYPE        0x21
#define USB_CDC_SET_ETH_PKT_FILTER  0x43

#define NCM_INT_EP_IDX          0
#define NCM_OUT_EP_IDX          1
#define NCM_IN_EP_IDX           2

#define NCM_SUBCLASS            0x0d                 // TODO -> usb_cdc.h
#define ETHERNET_FUNC_DESC_NCM  0x1a                 // TODO -> usb_cdc.h
#define NCM_DATA_PROTOCOL_NETWORK_TRANSFER_BLOCK 1

struct cdc_ncm_functional_descriptor {               // TODO -> usb_cdc.h
    uint8_t bFunctionLength;
    uint8_t bDescriptorType;
    uint8_t bDescriptorSubtype;
    uint16_t bcdNcmVersion;
    uint8_t bmNetworkCapabilities;
} __packed;


static uint8_t tx_buf[NET_ETH_MAX_FRAME_SIZE], rx_buf[NET_ETH_MAX_FRAME_SIZE];

struct usb_cdc_ncm_config {
    struct usb_association_descriptor iad;     // TUSB_DESC_INTERFACE_ASSOCIATION
    struct usb_if_descriptor if0;              // TUSB_DESC_INTERFACE
    struct cdc_header_descriptor if0_header;   // TUSB_DESC_CS_INTERFACE
    struct cdc_union_descriptor if0_union;     // TUSB_DESC_CS_INTERFACE
    struct cdc_ecm_descriptor if0_netfun_ecm;  // TUSB_DESC_CS_INTERFACE
    struct cdc_ncm_functional_descriptor if0_netfun_ncm;
    struct usb_ep_descriptor if0_int_ep;       // TUSB_DESC_ENDPOINT

    struct usb_if_descriptor if1_0;            // TUSB_DESC_INTERFACE

    struct usb_if_descriptor if1_1;            // TUSB_DESC_INTERFACE
    struct usb_ep_descriptor if1_1_in_ep;      // TUSB_DESC_ENDPOINT
    struct usb_ep_descriptor if1_1_out_ep;     // TUSB_DESC_ENDPOINT
} __packed;

USBD_CLASS_DESCR_DEFINE(primary, 0) struct usb_cdc_ncm_config cdc_ncm_cfg = {
    .iad = {
        .bLength = sizeof(struct usb_association_descriptor),
        .bDescriptorType = USB_DESC_INTERFACE_ASSOC,
        .bFirstInterface = 0,                                        // set by ncm_interface_config()
        .bInterfaceCount = 0x02,
        .bFunctionClass = USB_BCC_CDC_CONTROL,
        .bFunctionSubClass = NCM_SUBCLASS,
        .bFunctionProtocol = 0,
        .iFunction = 0,
    },
    /* Interface descriptor 0 */
    /* CDC Communication interface */
    .if0 = {
        .bLength = sizeof(struct usb_if_descriptor),
        .bDescriptorType = USB_DESC_INTERFACE,
        .bInterfaceNumber = 0,                                       // set by ncm_interface_config()
        .bAlternateSetting = 0,
        .bNumEndpoints = 1,
        .bInterfaceClass = USB_BCC_CDC_CONTROL,
        .bInterfaceSubClass = NCM_SUBCLASS,
        .bInterfaceProtocol = 0,
        .iInterface = 0,
    },
    /* Header Functional Descriptor */
    .if0_header = {
        .bFunctionLength = sizeof(struct cdc_header_descriptor),
        .bDescriptorType = USB_DESC_CS_INTERFACE,
        .bDescriptorSubtype = HEADER_FUNC_DESC,
        .bcdCDC = sys_cpu_to_le16(USB_SRN_1_1),
    },
    /* Union Functional Descriptor */
    .if0_union = {
        .bFunctionLength = sizeof(struct cdc_union_descriptor),
        .bDescriptorType = USB_DESC_CS_INTERFACE,
        .bDescriptorSubtype = UNION_FUNC_DESC,
        .bControlInterface = 0,                                      // set by ncm_interface_config()
        .bSubordinateInterface0 = 1,                                 // set by ncm_interface_config()
    },
    /* Ethernet Networking Functional descriptor I */
    .if0_netfun_ecm = {
        .bFunctionLength = sizeof(struct cdc_ecm_descriptor),
        .bDescriptorType = USB_DESC_CS_INTERFACE,
        .bDescriptorSubtype = ETHERNET_FUNC_DESC,
        .iMACAddress = 4,                                            // set by ncm_interface_config()
        .bmEthernetStatistics = sys_cpu_to_le32(0), /* None */
        .wMaxSegmentSize = sys_cpu_to_le16(NET_ETH_MAX_FRAME_SIZE),
        .wNumberMCFilters = sys_cpu_to_le16(0), /* None */
        .bNumberPowerFilters = 0, /* No wake up */
    },
    /* Ethernet Networking Functional descriptor II */
    .if0_netfun_ncm = {
        .bFunctionLength = sizeof(struct cdc_ncm_functional_descriptor),
        .bDescriptorType = USB_DESC_CS_INTERFACE,
        .bDescriptorSubtype = ETHERNET_FUNC_DESC_NCM,
        .bcdNcmVersion = sys_cpu_to_le16(0x100),
        .bmNetworkCapabilities = 0,
    },
    /* Notification EP Descriptor */
    .if0_int_ep = {
        .bLength = sizeof(struct usb_ep_descriptor),
        .bDescriptorType = USB_DESC_ENDPOINT,
        .bEndpointAddress = CDC_NCM_INT_EP_ADDR,
        .bmAttributes = USB_DC_EP_INTERRUPT,
        .wMaxPacketSize =
            sys_cpu_to_le16(
            CONFIG_CDC_ECM_INTERRUPT_EP_MPS),                        // TODO TinyUSB: 64
        .bInterval = 0x09,                                           // TODO TinyUSB: 50
    },

    /* Interface descriptor 1/0 */
    /* CDC Data Interface */
    .if1_0 = {
        .bLength = sizeof(struct usb_if_descriptor),
        .bDescriptorType = USB_DESC_INTERFACE,
        .bInterfaceNumber = 1,                                       // set by ncm_interface_config()
        .bAlternateSetting = 0,
        .bNumEndpoints = 0,
        .bInterfaceClass = USB_BCC_CDC_DATA,
        .bInterfaceSubClass = 0,
        .bInterfaceProtocol = NCM_DATA_PROTOCOL_NETWORK_TRANSFER_BLOCK,
        .iInterface = 0,
    },

    /* Interface descriptor 1/1 */
    /* CDC Data Interface */
    .if1_1 = {
        .bLength = sizeof(struct usb_if_descriptor),
        .bDescriptorType = USB_DESC_INTERFACE,
        .bInterfaceNumber = 1,                                       // set by ncm_interface_config()
        .bAlternateSetting = 1,
        .bNumEndpoints = 2,
        .bInterfaceClass = USB_BCC_CDC_DATA,
        .bInterfaceSubClass = 0,                                     // TODO was: ECM_SUBCLASS,
        .bInterfaceProtocol = NCM_DATA_PROTOCOL_NETWORK_TRANSFER_BLOCK,
        .iInterface = 0,
    },
    /* Data Endpoint IN */
    .if1_1_in_ep = {
        .bLength = sizeof(struct usb_ep_descriptor),
        .bDescriptorType = USB_DESC_ENDPOINT,
        .bEndpointAddress = CDC_NCM_IN_EP_ADDR,
        .bmAttributes = USB_DC_EP_BULK,
        .wMaxPacketSize =
            sys_cpu_to_le16(
            CONFIG_CDC_ECM_BULK_EP_MPS),
        .bInterval = 0x00,
    },
    /* Data Endpoint OUT */
    .if1_1_out_ep = {
        .bLength = sizeof(struct usb_ep_descriptor),
        .bDescriptorType = USB_DESC_ENDPOINT,
        .bEndpointAddress = CDC_NCM_OUT_EP_ADDR,
        .bmAttributes = USB_DC_EP_BULK,
        .wMaxPacketSize =
            sys_cpu_to_le16(
            CONFIG_CDC_ECM_BULK_EP_MPS),
        .bInterval = 0x00,
    },
};


struct usb_cdc_ncm_mac_descr {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bString[USB_BSTRING_LENGTH(CONFIG_USB_DEVICE_NETWORK_ECM_MAC)];
} __packed;

USBD_STRING_DESCR_USER_DEFINE(primary) struct usb_cdc_ncm_mac_descr utf16le_mac = {
    .bLength = USB_STRING_DESCRIPTOR_LENGTH(
            CONFIG_USB_DEVICE_NETWORK_ECM_MAC),
    .bDescriptorType = USB_DESC_STRING,
    .bString = CONFIG_USB_DEVICE_NETWORK_ECM_MAC
};



static uint8_t ncm_get_first_iface_number(void)
{
    return cdc_ncm_cfg.if0.bInterfaceNumber;
}   // ncm_get_first_iface_number



static void ncm_int_in(uint8_t ep, enum usb_dc_ep_cb_status_code ep_status)
{
    LOG_DBG("EP 0x%x status %d", ep, ep_status);
}   // ncm_int_in



static struct usb_ep_cfg_data ncm_ep_data[] = {
    /* Configuration NCM */
    {
        .ep_cb = ncm_int_in,
        .ep_addr = CDC_NCM_INT_EP_ADDR
    },
    {
        /* high-level transfer mgmt */
        .ep_cb = usb_transfer_ep_callback,
        .ep_addr = CDC_NCM_OUT_EP_ADDR
    },
    {
        /* high-level transfer mgmt */
        .ep_cb = usb_transfer_ep_callback,
        .ep_addr = CDC_NCM_IN_EP_ADDR
    },
};



static int ncm_class_handler(struct usb_setup_packet *setup, int32_t *len,
                             uint8_t **data)
{
    LOG_DBG("len %d req_type 0x%x req 0x%x enabled %u",
            *len, setup->bmRequestType, setup->bRequest,
            netusb_enabled());

    if (!netusb_enabled()) {
        LOG_ERR("interface disabled");
        return -ENODEV;
    }

    if (setup->bmRequestType != USB_CDC_ECM_REQ_TYPE) {
        /*
         * Only host-to-device, type class, recipient interface
         * requests are accepted.
         */
        return -EINVAL;
    }

    if (setup->bRequest == USB_CDC_SET_ETH_PKT_FILTER) {
        LOG_INF("Set Interface %u Packet Filter 0x%04x not supported",
            setup->wIndex, setup->wValue);
        return 0;
    }

    return -ENOTSUP;
}   // ncm_class_handler



/* Retrieve expected pkt size from ethernet/ip header */
static size_t ncm_eth_size(void *ncm_pkt, size_t len)
{
    struct net_eth_hdr *hdr = (void *)ncm_pkt;
    uint8_t *ip_data = (uint8_t *)ncm_pkt + sizeof(struct net_eth_hdr);
    uint16_t ip_len;

    if (len < NET_IPV6H_LEN + sizeof(struct net_eth_hdr)) {
        /* Too short */
        return 0;
    }

    switch (ntohs(hdr->type)) {
    case NET_ETH_PTYPE_IP:
    case NET_ETH_PTYPE_ARP:
        ip_len = ntohs(((struct net_ipv4_hdr *)ip_data)->len);
        break;
    case NET_ETH_PTYPE_IPV6:
        ip_len = ntohs(((struct net_ipv6_hdr *)ip_data)->len);
        break;
    default:
        LOG_DBG("Unknown hdr type 0x%04x", hdr->type);
        return 0;
    }

    return sizeof(struct net_eth_hdr) + ip_len;
}   // ncm_eth_size



static int ncm_send(struct net_pkt *pkt)
{
    size_t len = net_pkt_get_len(pkt);
    int ret;

    if (VERBOSE_DEBUG) {
        net_pkt_hexdump(pkt, "<");
    }

    if (len > sizeof(tx_buf)) {
        LOG_WRN("Trying to send too large packet, drop");
        return -ENOMEM;
    }

    if (net_pkt_read(pkt, tx_buf, len)) {
        return -ENOBUFS;
    }

    /* transfer data to host */
    ret = usb_transfer_sync(ncm_ep_data[NCM_IN_EP_IDX].ep_addr,
                tx_buf, len, USB_TRANS_WRITE);
    if (ret != len) {
        LOG_ERR("Transfer failure");
        return -EINVAL;
    }

    return 0;
}   // ncm_send



static void ncm_read_cb(uint8_t ep, int size, void *priv)
{
    struct net_pkt *pkt;

    if (size <= 0) {
        goto done;
    }

    /* Linux considers by default that network usb device controllers are
     * not able to handle Zero Length Packet (ZLP) and then generates
     * a short packet containing a null byte. Handle by checking the IP
     * header length and dropping the extra byte.
     */
    if (rx_buf[size - 1] == 0U) { /* last byte is null */
        if (ncm_eth_size(rx_buf, size) == (size - 1)) {
            /* last byte has been appended as delimiter, drop it */
            size--;
        }
    }

    pkt = net_pkt_rx_alloc_with_buffer(netusb_net_iface(), size, AF_UNSPEC,
                       0, K_FOREVER);
    if (!pkt) {
        LOG_ERR("no memory for network packet");
        goto done;
    }

    if (net_pkt_write(pkt, rx_buf, size)) {
        LOG_ERR("Unable to write into pkt");
        net_pkt_unref(pkt);
        goto done;
    }

    if (VERBOSE_DEBUG) {
        net_pkt_hexdump(pkt, ">");
    }

    netusb_recv(pkt);

done:
    usb_transfer(ncm_ep_data[NCM_OUT_EP_IDX].ep_addr, rx_buf,
                 sizeof(rx_buf), USB_TRANS_READ, ncm_read_cb, NULL);
}   // ncm_read_cb



static int ncm_connect(bool connected)
{
    if (connected) {
        ncm_read_cb(ncm_ep_data[NCM_OUT_EP_IDX].ep_addr, 0, NULL);
    } else {
        /* Cancel any transfer */
        usb_cancel_transfer(ncm_ep_data[NCM_OUT_EP_IDX].ep_addr);
        usb_cancel_transfer(ncm_ep_data[NCM_IN_EP_IDX].ep_addr);
    }

    return 0;
}   // ncm_connect



static inline void ncm_status_interface(const uint8_t *desc)
{
    static const struct netusb_function ncm_function = {
        .connect_media = ncm_connect,
        .send_pkt = ncm_send,
    };
    const struct usb_if_descriptor *if_desc = (void *)desc;
    uint8_t iface_num = if_desc->bInterfaceNumber;
    uint8_t alt_set = if_desc->bAlternateSetting;

    LOG_DBG("iface %u alt_set %u", iface_num, if_desc->bAlternateSetting);

    /* First interface is CDC Comm interface */
    if (iface_num != ncm_get_first_iface_number() + 1 || !alt_set) {
        LOG_DBG("Skip iface_num %u alt_set %u", iface_num, alt_set);
        return;
    }

    netusb_enable(&ncm_function);
}   // ncm_status_interface



static void ncm_status_cb(struct usb_cfg_data *cfg,
                          enum usb_dc_status_code status,
                          const uint8_t *param)
{
    ARG_UNUSED(cfg);

    /* Check the USB status and do needed action if required */
    switch (status) {
        case USB_DC_DISCONNECTED:
            LOG_DBG("USB device disconnected");
            netusb_disable();
            break;

        case USB_DC_INTERFACE:
            LOG_DBG("USB interface selected");
            ncm_status_interface(param);
            break;

        case USB_DC_ERROR:
        case USB_DC_RESET:
        case USB_DC_CONNECTED:
        case USB_DC_CONFIGURED:
        case USB_DC_SUSPEND:
        case USB_DC_RESUME:
            LOG_DBG("USB unhandled state: %d", status);
            break;

        case USB_DC_SOF:
            break;

        case USB_DC_UNKNOWN:
        default:
            LOG_DBG("USB unknown state: %d", status);
            break;
    }
}   // ncm_status_cb



static void ncm_interface_config(struct usb_desc_header *head,
                                 uint8_t bInterfaceNumber)
/**
 * Patch descriptor to hold correct information
 */
{
    ARG_UNUSED(head);

    int idx = usb_get_str_descriptor_idx(&utf16le_mac);
    if (idx) {
        LOG_DBG("fixup string %d", idx);
        cdc_ncm_cfg.if0_netfun_ecm.iMACAddress = idx;
    }

    cdc_ncm_cfg.if0.bInterfaceNumber = bInterfaceNumber;
    cdc_ncm_cfg.if0_union.bControlInterface = bInterfaceNumber;
    cdc_ncm_cfg.if0_union.bSubordinateInterface0 = bInterfaceNumber + 1;
    cdc_ncm_cfg.if1_0.bInterfaceNumber = bInterfaceNumber + 1;
    cdc_ncm_cfg.if1_1.bInterfaceNumber = bInterfaceNumber + 1;
    cdc_ncm_cfg.iad.bFirstInterface = bInterfaceNumber;
}   // ncm_interface_config



USBD_DEFINE_CFG_DATA(cdc_ncm_config) = {
    .usb_device_description = NULL,
    .interface_config = ncm_interface_config,
    .interface_descriptor = &cdc_ncm_cfg.if0,
    .cb_usb_status = ncm_status_cb,
    .interface = {
        .class_handler = ncm_class_handler,
        .custom_handler = NULL,
        .vendor_handler = NULL,
    },
    .num_endpoints = ARRAY_SIZE(ncm_ep_data),
    .endpoint = ncm_ep_data,
};
