/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(usb_ecm, CONFIG_USB_DEVICE_NETWORK_LOG_LEVEL);

/* Enable verbose debug printing extra hexdumps */
#define VERBOSE_DEBUG   0

#include <zephyr/net/net_pkt.h>
#include <zephyr/net/ethernet.h>
#include <net_private.h>

#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_cdc.h>
#include <usb_descriptor.h>

#include "netusb.h"
#include "ncm.h"

#define USB_CDC_ECM_REQ_TYPE        0x21
#define USB_CDC_SET_ETH_PKT_FILTER  0x43

#define ECM_INT_EP_IDX          0
#define ECM_OUT_EP_IDX          1
#define ECM_IN_EP_IDX           2


static uint8_t tx_buf[CONFIG_CDC_NCM_XMT_NTB_MAX_SIZE], rx_buf[CONFIG_CDC_NCM_RCV_NTB_MAX_SIZE];

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

//
// NCM Class Descriptor
// TODO order is not according to chapter 7.4 in spec
USBD_CLASS_DESCR_DEFINE(primary, 0) struct usb_cdc_ncm_config cdc_ncm_cfg = {
    // Interface Association Descriptor
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
    // Communication Class Interface Descriptor 0
    // CDC Communication interface
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
    // Functional Descriptors for the Communication Class Interface
    // CDC Header Functional Descriptor
    .if0_header = {
        .bFunctionLength = sizeof(struct cdc_header_descriptor),
        .bDescriptorType = USB_DESC_CS_INTERFACE,
        .bDescriptorSubtype = HEADER_FUNC_DESC,
        .bcdCDC = sys_cpu_to_le16(USB_SRN_1_1),
    },
    // CDC Union Functional Descriptor
    .if0_union = {
        .bFunctionLength = sizeof(struct cdc_union_descriptor),
        .bDescriptorType = USB_DESC_CS_INTERFACE,
        .bDescriptorSubtype = UNION_FUNC_DESC,
        .bControlInterface = 0,                                      // set by ncm_interface_config()
        .bSubordinateInterface0 = 1,                                 // set by ncm_interface_config()
    },
    // CDC Ethernet Networking Functional descriptor
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
    // NCM Functional descriptor
    .if0_netfun_ncm = {
        .bFunctionLength = sizeof(struct cdc_ncm_functional_descriptor),
        .bDescriptorType = USB_DESC_CS_INTERFACE,
        .bDescriptorSubtype = ETHERNET_FUNC_DESC_NCM,
        .bcdNcmVersion = sys_cpu_to_le16(0x100),
        .bmNetworkCapabilities = 0,
    },

    // Notification EP Descriptor
    .if0_int_ep = {
        .bLength = sizeof(struct usb_ep_descriptor),
        .bDescriptorType = USB_DESC_ENDPOINT,
        .bEndpointAddress = CDC_NCM_INT_EP_ADDR,
        .bmAttributes = USB_DC_EP_INTERRUPT,
        .wMaxPacketSize = sys_cpu_to_le16(CONFIG_CDC_ECM_INTERRUPT_EP_MPS),
        .bInterval = 0x09,
    },

    // Interface descriptor 1/0
    // CDC Data Interface
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

    // Interface descriptor 1/1
    // CDC Data Interface
    .if1_1 = {
        .bLength = sizeof(struct usb_if_descriptor),
        .bDescriptorType = USB_DESC_INTERFACE,
        .bInterfaceNumber = 1,                                       // set by ncm_interface_config()
        .bAlternateSetting = 1,
        .bNumEndpoints = 2,
        .bInterfaceClass = USB_BCC_CDC_DATA,
        .bInterfaceSubClass = 0,
        .bInterfaceProtocol = NCM_DATA_PROTOCOL_NETWORK_TRANSFER_BLOCK,
        .iInterface = 0,
    },
    // Data Endpoint IN
    .if1_1_in_ep = {
        .bLength = sizeof(struct usb_ep_descriptor),
        .bDescriptorType = USB_DESC_ENDPOINT,
        .bEndpointAddress = CDC_NCM_IN_EP_ADDR,
        .bmAttributes = USB_DC_EP_BULK,
        .wMaxPacketSize = sys_cpu_to_le16(CONFIG_CDC_ECM_BULK_EP_MPS),
        .bInterval = 0x00,
    },
    // Data Endpoint OUT
    .if1_1_out_ep = {
        .bLength = sizeof(struct usb_ep_descriptor),
        .bDescriptorType = USB_DESC_ENDPOINT,
        .bEndpointAddress = CDC_NCM_OUT_EP_ADDR,
        .bmAttributes = USB_DC_EP_BULK,
        .wMaxPacketSize = sys_cpu_to_le16(CONFIG_CDC_ECM_BULK_EP_MPS),
        .bInterval = 0x00,
    },
};

typedef struct {
//    // recv handling
//    __aligned(4) recv_ntb_t recv_ntb[RECV_NTB_N];  //!< actual recv NTBs
//    recv_ntb_t *recv_free_ntb[RECV_NTB_N];         //!< free list of recv NTBs
//    recv_ntb_t *recv_ready_ntb[RECV_NTB_N];        //!< NTBs waiting for transmission to netusb
//    recv_ntb_t *recv_usbdrv_ntb;                   //!< buffer for the running transfer usbdrv -> NCM driver
//    recv_ntb_t *recv_netusb_ntb;                   //!< buffer for the running transfer NCM driver -> netusb
//    uint16_t    recv_netusb_ntb_datagram_ndx;      //!< index into \a recv_netusb_ntb_datagram
//
//    // xmit handling
//    __aligned(4) xmit_ntb_t xmit_ntb[XMIT_NTB_N];  //!< actual xmit NTBs
//    xmit_ntb_t *xmit_free_ntb[XMIT_NTB_N];         //!< free list of xmit NTBs
//    xmit_ntb_t *xmit_ready_ntb[XMIT_NTB_N];        //!< NTBs waiting for transmission to usbdrv
//    xmit_ntb_t *xmit_usbdrv_ntb;                   //!< buffer for the running transfer NCM driver -> usbdrv
//    xmit_ntb_t *xmit_netusb_ntb;                   //!< buffer for the running transfer netusb -> NCM driver
//    uint16_t    xmit_sequence;                     //!< NTB sequence counter
//    uint16_t    xmit_netusb_ntb_datagram_ndx;      //!< index into \a xmit_netusb_ntb_datagram

    // notification handling
    enum {
        IF_STATE_INIT = 0,
        IF_STATE_FIRST_SKIPPED,
        IF_STATE_SPEED_SENT,
        IF_STATE_DONE,
    } if_state;                                    //!< interface state

    // misc
    uint8_t     itf_data_alt;                      //!< ==0 -> no endpoints, i.e. no network traffic, ==1 -> normal operation with two endpoints (spec, chapter 5.3)
} ncm_interface_t;


__aligned(4) static ncm_interface_t ncm_interface;


/**
 * This is the NTB parameter structure
 */
__aligned(4) static const ntb_parameters_t ntb_parameters = {
    .wLength                 = sys_cpu_to_le16(sizeof(ntb_parameters_t)),
    .bmNtbFormatsSupported   = sys_cpu_to_le16(0x01),                                 // 16-bit NTB supported
    .dwNtbInMaxSize          = sys_cpu_to_le32(CONFIG_CDC_NCM_XMT_NTB_MAX_SIZE),
    .wNdbInDivisor           = sys_cpu_to_le16(4),
    .wNdbInPayloadRemainder  = sys_cpu_to_le16(0),
    .wNdbInAlignment         = sys_cpu_to_le16(CONFIG_CDC_NCM_ALIGNMENT),
    .wReserved               = sys_cpu_to_le16(0),
    .dwNtbOutMaxSize         = sys_cpu_to_le32(CONFIG_CDC_NCM_RCV_NTB_MAX_SIZE),
    .wNdbOutDivisor          = sys_cpu_to_le16(4),
    .wNdbOutPayloadRemainder = sys_cpu_to_le16(0),
    .wNdbOutAlignment        = sys_cpu_to_le16(CONFIG_CDC_NCM_ALIGNMENT),
    .wNtbOutMaxDatagrams     = sys_cpu_to_le16(1)
};


__aligned(4) static ncm_notify_network_connection_t ncm_notify_connected = {
        .header = {
                .RequestType = {
                        .recipient = USB_REQTYPE_RECIPIENT_INTERFACE,
                        .type      = USB_REQTYPE_TYPE_CLASS,
                        .direction = USB_REQTYPE_DIR_TO_HOST
                },
                .bRequest = NCM_NOTIFICATION_NETWORK_CONNECTION,
                .wValue   = sys_cpu_to_le16(1) /* Connected */,
                .wLength  = sys_cpu_to_le16(0),
        },
};

__aligned(4) static ncm_notify_connection_speed_change_t ncm_notify_speed_change = {
        .header = {
                .RequestType = {
                        .recipient = USB_REQTYPE_RECIPIENT_INTERFACE,
                        .type      = USB_REQTYPE_TYPE_CLASS,
                        .direction = USB_REQTYPE_DIR_TO_HOST
                },
                .bRequest = NCM_NOTIFICATION_CONNECTION_SPEED_CHANGE,
                .wLength  = sys_cpu_to_le16(8),
        },
        .downlink = sys_cpu_to_le32(12000000),
        .uplink   = sys_cpu_to_le32(12000000),
};


static uint8_t ecm_get_first_iface_number(void)
{
    return cdc_ncm_cfg.if0.bInterfaceNumber;
}

static struct usb_ep_cfg_data ecm_ep_data[] = {
    /* Configuration ECM */
    {
        .ep_cb = usb_transfer_ep_callback,
        .ep_addr = CDC_ECM_INT_EP_ADDR
    },
    {
        /* high-level transfer mgmt */
        .ep_cb = usb_transfer_ep_callback,
        .ep_addr = CDC_ECM_OUT_EP_ADDR
    },
    {
        /* high-level transfer mgmt */
        .ep_cb = usb_transfer_ep_callback,
        .ep_addr = CDC_ECM_IN_EP_ADDR
    },
};

static int ecm_class_handler(struct usb_setup_packet *setup, int32_t *len,
                 uint8_t **data)
{
    LOG_DBG("len %d req_type 0x%x req 0x%x enabled %u",
            *len, setup->bmRequestType, setup->bRequest,
            netusb_enabled());

    switch (setup->RequestType.type)
    {
        case USB_REQTYPE_TYPE_STANDARD:
            LOG_DBG("  USB_REQTYPE_TYPE_STANDARD: %d %d %d %d", setup->bRequest, setup->wValue, setup->wIndex, setup->wLength);
            break;

        case USB_REQTYPE_TYPE_CLASS:
            LOG_DBG("  USB_REQTYPE_TYPE_CLASS: %d %d %d %d", setup->bRequest, setup->wLength, setup->wIndex, setup->wValue);

            if (setup->bRequest == NCM_GET_NTB_PARAMETERS)
            {
                LOG_DBG("    NCM_GET_NTB_PARAMETERS");
                *len = sizeof(ntb_parameters);
                *data = (uint8_t *)&ntb_parameters;
                return 0;
            }
            else if (setup->bRequest == NCM_SET_ETHERNET_PACKET_FILTER)
            {
                LOG_WRN("    NCM_SET_ETHERNET_PACKET_FILTER (not supported)");
                return 0;
            }
            else if (setup->bRequest == NCM_GET_NTB_INPUT_SIZE)
            {
                LOG_ERR("    NCM_GET_NTB_INPUT_SIZE (not supported, but required)");
                return -ENOTSUP;
            }
            else if (setup->bRequest == NCM_SET_NTB_INPUT_SIZE)
            {
                uint32_t **p = (uint32_t **)data;
                LOG_ERR("    NCM_SET_NTB_INPUT_SIZE (not supported, but required), len:%u", (unsigned)**p);
                return -ENOTSUP;
            }
            LOG_WRN("    not supported: %d", setup->bRequest);
            return -ENOTSUP;

        default:
            // unsupported request
            return -ENOTSUP;
    }

    if ( !netusb_enabled())
    {
        LOG_ERR("interface disabled");
        return -ENODEV;
    }

    if (setup->bRequest == NCM_SET_ETHERNET_PACKET_FILTER) {
        LOG_DBG("Set Interface %u Packet Filter 0x%04x not supported",
                setup->wIndex, setup->wValue);
        return 0;
    }

    return -ENOTSUP;
}

static int ecm_custom_handler(struct usb_setup_packet *setup, int32_t *len,
                 uint8_t **data)
{
    LOG_DBG("len %d req_type 0x%x req 0x%x enabled %u",
        *len, setup->bmRequestType, setup->bRequest,
        netusb_enabled());

    return -EINVAL;
}

static int ecm_vendor_handler(struct usb_setup_packet *setup, int32_t *len,
                 uint8_t **data)
{
    LOG_DBG("len %d req_type 0x%x req 0x%x enabled %u",
        *len, setup->bmRequestType, setup->bRequest,
        netusb_enabled());

    return -EINVAL;
}

/* Retrieve expected pkt size from ethernet/ip header */
static size_t ecm_eth_size(void *ecm_pkt, size_t len)
{
    struct net_eth_hdr *hdr = (void *)ecm_pkt;
    uint8_t *ip_data = (uint8_t *)ecm_pkt + sizeof(struct net_eth_hdr);
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
}

static int ecm_send(struct net_pkt *pkt)
{
    size_t len = net_pkt_get_len(pkt);
    int ret;
    xmit_ntb_t *ntb = (xmit_ntb_t *)tx_buf;
    static uint16_t seq;

    ntb->nth.dwSignature = NTH16_SIGNATURE;
    ntb->nth.wHeaderLength = sizeof(nth16_t);
    ntb->nth.wSequence = ++seq;
    //ntb->nth.wBlockLength = xx;
    ntb->nth.wNdpIndex = 0x0c;

    ntb->ndp.dwSignature = NDP16_SIGNATURE_NCM0;
    ntb->ndp.wLength = 16;
    ntb->ndp.wNextNdpIndex = 0;

    ntb->ndp_datagram[0].wDatagramIndex = ntb->nth.wHeaderLength + ntb->ndp.wLength;
    ntb->ndp_datagram[0].wDatagramLength = len;
    ntb->ndp_datagram[1].wDatagramIndex = 0;
    ntb->ndp_datagram[1].wDatagramLength = 0;

    ntb->nth.wBlockLength = ntb->ndp_datagram[0].wDatagramIndex + ntb->ndp_datagram[0].wDatagramLength;

    if (net_pkt_read(pkt, ntb->data + ntb->ndp_datagram[0].wDatagramIndex, len)) {
        return -ENOBUFS;
    }

    ret = usb_transfer_sync(ecm_ep_data[ECM_IN_EP_IDX].ep_addr,
                            tx_buf, ntb->nth.wBlockLength,
#if 0
                            USB_TRANS_WRITE | USB_TRANS_NO_ZLP);
#else
                            // needs ZLP, otherwise there are errors in the log output
                            USB_TRANS_WRITE);
#endif
    if (ret != ntb->nth.wBlockLength) {
        LOG_ERR("Transfer failure %d", ret);
        return -EINVAL;
    }

    return 0;
}



static void ecm_read_cb(uint8_t ep, int size, void *priv)
{
    struct net_pkt *pkt;
    nth16_t *ntb;
    ndp16_datagram_t *ndp_datagram;

    LOG_DBG("%d %d", ep, size);

    if (size <= 0) {
        goto done;
    }

    // NO VALIDITY CHECKING

    ntb = (nth16_t *)rx_buf;
    ndp_datagram = (ndp16_datagram_t *)(rx_buf + ntb->wNdpIndex + sizeof(ndp16_t));

    uint16_t start = ndp_datagram[0].wDatagramIndex;
    uint16_t len   = ndp_datagram[0].wDatagramLength;

    /* Linux considers by default that network usb device controllers are
     * not able to handle Zero Length Packet (ZLP) and then generates
     * a short packet containing a null byte. Handle by checking the IP
     * header length and dropping the extra byte.
     */
    if (rx_buf[start + len - 1] == 0U) { /* last byte is null */
        if (ecm_eth_size(rx_buf + start, len) == (len - 1)) {
            /* last byte has been appended as delimiter, drop it */
            LOG_WRN("removed trailing byte");
            len--;
        }
    }

    pkt = net_pkt_rx_alloc_with_buffer(netusb_net_iface(), len, AF_UNSPEC,
                                       0, K_FOREVER);
    if (!pkt) {
        LOG_ERR("no memory for network packet");
        goto done;
    }

    if (net_pkt_write(pkt, rx_buf + start, len)) {
        LOG_ERR("Unable to write into pkt");
        net_pkt_unref(pkt);
        goto done;
    }

    if (VERBOSE_DEBUG) {
        net_pkt_hexdump(pkt, ">");
    }

    netusb_recv(pkt);

done:
    usb_transfer(ecm_ep_data[ECM_OUT_EP_IDX].ep_addr, rx_buf,
             sizeof(rx_buf), USB_TRANS_READ, ecm_read_cb, NULL);
}



static int ecm_connect(bool connected)
{
    if (connected) {
        ecm_read_cb(ecm_ep_data[ECM_OUT_EP_IDX].ep_addr, 0, NULL);
    } else {
        /* Cancel any transfer */
        usb_cancel_transfer(ecm_ep_data[ECM_OUT_EP_IDX].ep_addr);
        usb_cancel_transfer(ecm_ep_data[ECM_IN_EP_IDX].ep_addr);
    }

    return 0;
}

static struct netusb_function ecm_function = {
    .connect_media = ecm_connect,
    .send_pkt = ecm_send,
};



static void ncm_status_interface_cb(uint8_t ep, int tsize, void *priv)
/**
 * Callback for status packets.
 *
 * \note
 *    Not sure if all this is correct, but there is at least some packet traffic ;-)
 */
{
    LOG_DBG("data transferred: %d %d %d", ep, tsize, ncm_interface.if_state);

    if (ncm_interface.if_state == IF_STATE_FIRST_SKIPPED)
    {
        ncm_interface.if_state = IF_STATE_SPEED_SENT;

        ncm_notify_speed_change.header.wIndex = ecm_get_first_iface_number();
        usb_transfer(ep, (uint8_t *)&ncm_notify_speed_change, sizeof(ncm_notify_speed_change),
                     USB_TRANS_WRITE,
                     ncm_status_interface_cb, NULL);
    }
    else if (ncm_interface.if_state == IF_STATE_SPEED_SENT)
    {
        ncm_interface.if_state = IF_STATE_DONE;

        ncm_notify_connected.header.wIndex = ecm_get_first_iface_number();
        usb_transfer(ep, (uint8_t *)&ncm_notify_connected, sizeof(ncm_notify_connected),
                     USB_TRANS_WRITE,
                     ncm_status_interface_cb, NULL);
    }
}   // ncm_status_interface_cb



static inline void ecm_status_interface(const uint8_t *desc)
{
    const struct usb_if_descriptor *if_desc = (void *)desc;
    uint8_t iface_num = if_desc->bInterfaceNumber;
    uint8_t alt_set = if_desc->bAlternateSetting;

    LOG_DBG("iface %u alt_set %u", iface_num, if_desc->bAlternateSetting);

    if (iface_num == ecm_get_first_iface_number() + 1)
    {
        ncm_interface.itf_data_alt = alt_set;
    }

    /* First interface is CDC Comm interface */
    if (iface_num != ecm_get_first_iface_number() + 1  ||  alt_set == 0)
    {
        LOG_DBG("Skip iface_num %u alt_set %u", iface_num, alt_set);
        return;
    }

    if (ncm_interface.if_state == IF_STATE_INIT)
    {
        ncm_interface.if_state = IF_STATE_FIRST_SKIPPED;
        LOG_DBG("Skip first iface enable");
        return;
    }

    netusb_enable(&ecm_function);
    ncm_status_interface_cb(ecm_ep_data[ECM_INT_EP_IDX].ep_addr, 0, NULL);
}



static void ecm_status_cb(struct usb_cfg_data *cfg,
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
        ecm_status_interface(param);
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
}

struct usb_cdc_ecm_mac_descr {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bString[USB_BSTRING_LENGTH(CONFIG_USB_DEVICE_NETWORK_ECM_MAC)];
} __packed;

USBD_STRING_DESCR_USER_DEFINE(primary) struct usb_cdc_ecm_mac_descr utf16le_mac = {
    .bLength = USB_STRING_DESCRIPTOR_LENGTH(
            CONFIG_USB_DEVICE_NETWORK_ECM_MAC),
    .bDescriptorType = USB_DESC_STRING,
    .bString = CONFIG_USB_DEVICE_NETWORK_ECM_MAC
};

static void ecm_interface_config(struct usb_desc_header *head,
                 uint8_t bInterfaceNumber)
{
    int idx = usb_get_str_descriptor_idx(&utf16le_mac);

    ARG_UNUSED(head);

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
}

USBD_DEFINE_CFG_DATA(cdc_ecm_config) = {
    .usb_device_description = NULL,
    .interface_config = ecm_interface_config,
    .interface_descriptor = &cdc_ncm_cfg.if0,
    .cb_usb_status = ecm_status_cb,
    .interface = {
        .class_handler = ecm_class_handler,
        .custom_handler = ecm_custom_handler,
        .vendor_handler = ecm_vendor_handler,
    },
    .num_endpoints = ARRAY_SIZE(ecm_ep_data),
    .endpoint = ecm_ep_data,
};
