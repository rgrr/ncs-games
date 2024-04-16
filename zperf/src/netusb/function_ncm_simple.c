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

#include <assert.h>

#include "netusb.h"
#include "ncm.h"

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
        .wMaxPacketSize = 64,
        .bInterval = 50,
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


// forward declarations
static int ncm_connect(bool connected);
static int ncm_send(struct net_pkt *pkt);
static void ncm_read_cb(uint8_t ep, int xferred_bytes, void *priv);


static const struct netusb_function ncm_function = {
    .connect_media = ncm_connect,
    .send_pkt = ncm_send,
};


struct usb_cdc_ncm_mac_descr {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bString[USB_BSTRING_LENGTH(CONFIG_USB_DEVICE_NETWORK_ECM_MAC)];
} __packed;

USBD_STRING_DESCR_USER_DEFINE(primary) struct usb_cdc_ncm_mac_descr utf16le_mac = {
    .bLength = USB_STRING_DESCRIPTOR_LENGTH( CONFIG_USB_DEVICE_NETWORK_ECM_MAC),
    .bDescriptorType = USB_DESC_STRING,
    .bString = CONFIG_USB_DEVICE_NETWORK_ECM_MAC
};


// calculate alignment of xmit datagrams within an NTB
#define XMIT_ALIGN_OFFSET(x)   ((CONFIG_CDC_NCM_ALIGNMENT - ((x) & (CONFIG_CDC_NCM_ALIGNMENT - 1))) & (CONFIG_CDC_NCM_ALIGNMENT - 1))

typedef struct {
    // recv handling
    __aligned(4) recv_ntb_t  recv_usbdrv_ntb;                   //!< buffer for the running transfer usbdrv -> NCM driver

    // xmit handling
    __aligned(4) xmit_ntb_t  xmit_usbdrv_ntb;                   //!< buffer for the running transfer NCM driver -> usbdrv
    uint16_t    xmit_sequence;                     //!< NTB sequence counter

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
    .wNtbOutMaxDatagrams     = sys_cpu_to_le16(1)                                     // CONFIG_CDC_NCM_RCV_MAX_DATAGRAMS_PER_NTB
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


void int_cb(uint8_t ep, enum usb_dc_ep_cb_status_code code)
{
    LOG_ERR("ep: %d, code: %d", ep, code);
}

static struct usb_ep_cfg_data ncm_ep_data[] = {
    /* Configuration NCM */
    {
#if 0
        .ep_cb = int_cb,
#else
        .ep_cb = usb_transfer_ep_callback,
#endif
        .ep_addr = CDC_NCM_INT_EP_ADDR
    },
    {
        .ep_cb = usb_transfer_ep_callback,
        .ep_addr = CDC_NCM_OUT_EP_ADDR
    },
    {
        .ep_cb = usb_transfer_ep_callback,
        .ep_addr = CDC_NCM_IN_EP_ADDR
    },
};


//-----------------------------------------------------------------------------
//
// everything about packet transmission (driver -> netusb)
//


static void xmit_insert_required_zlp(uint32_t xferred_bytes)
/**
 * Transmit a ZLP if required
 *
 * \note
 *    Insertion of the ZLPs is a little bit different then described in the spec.
 *    But the below implementation actually works.
 *
 * \pre
 *    This must be called from netd_xfer_cb() so that ep_in is ready
 */
{
#if 0
    LOG_DBG("(%u)", (unsigned)xferred_bytes);

    if (xferred_bytes == 0  ||  xferred_bytes % CONFIG_CDC_ECM_BULK_EP_MPS != 0) {
        return;
    }

    assert(ncm_interface.itf_data_alt == 1);
    assert( !usb_transfer_is_busy(ncm_ep_data[NCM_IN_EP_IDX].ep_addr));

    LOG_WRN("  insert ZLP");

    // start transmission of the ZLP
    int r = usb_transfer_sync(ncm_ep_data[NCM_IN_EP_IDX].ep_addr, NULL,
                              0, USB_TRANS_WRITE);
    if (r != 0)
    {
        LOG_ERR("cannot start transmission: %d", r);
    }
#endif
}   // xmit_insert_required_zlp



static void xmit_setup_next_usbdrv_ntb(void)
/**
 * Setup an NTB for the USB driver
 */
{
    LOG_DBG("");

    xmit_ntb_t *ntb = &ncm_interface.xmit_usbdrv_ntb;

    // Fill in NTB header
    ntb->nth.dwSignature   = sys_cpu_to_le32(NTH16_SIGNATURE);
    ntb->nth.wHeaderLength = sys_cpu_to_le16(sizeof(ntb->nth));
    ntb->nth.wSequence     = sys_cpu_to_le16(ncm_interface.xmit_sequence++);
    ntb->nth.wBlockLength  = sys_cpu_to_le16(sizeof(ntb->nth) + sizeof(ntb->ndp) + sizeof(ntb->ndp_datagram));
    ntb->nth.wNdpIndex     = sys_cpu_to_le16(sizeof(ntb->nth));

    // Fill in NDP16 header and terminator
    ntb->ndp.dwSignature   = sys_cpu_to_le32(NDP16_SIGNATURE_NCM0);
    ntb->ndp.wLength       = sys_cpu_to_le16(sizeof(ntb->ndp) + sizeof(ntb->ndp_datagram));
    ntb->ndp.wNextNdpIndex = sys_cpu_to_le16(0);

    ntb->ndp_datagram[1].wDatagramLength = 0;   // TODO actually not required
    ntb->ndp_datagram[1].wDatagramIndex  = 0;

    memset(ntb->ndp_datagram, 0, sizeof(ntb->ndp_datagram));
}   // xmit_setup_next_usbdrv_ntb


//-----------------------------------------------------------------------------
//
// all the recv_*() stuff (netusb -> NCM driver -> USB driver)
//


static void recv_start_new_reception(uint8_t ep)
/**
 * If possible, start a new reception usbdrv -> NCM.
 */
{
    LOG_DBG("%d", ep);

    if (ncm_interface.itf_data_alt != 1)
    {
        return;
    }

    // initiate transfer
    LOG_DBG("  start reception");
    int r = usb_transfer(ep, (uint8_t *)&ncm_interface.recv_usbdrv_ntb,
                         CONFIG_CDC_NCM_RCV_NTB_MAX_SIZE, USB_TRANS_READ, ncm_read_cb, NULL);
    if (r != 0)
    {
        LOG_ERR("cannot start reception: %d", r);
    }
}   // recv_start_new_reception



static bool recv_validate_datagram(const recv_ntb_t *ntb, uint32_t len)
/**
 * Validate incoming datagram.
 * \return true if valid
 *
 * \note
 *    \a ndp16->wNextNdpIndex != 0 is not supported
 */
{
    const nth16_t *nth16 = &(ntb->nth);

    LOG_DBG("%p, %d", ntb, (int)len);

    //
    // check header
    //
    if (len < sizeof(ntb->nth))
    {
        LOG_ERR("  ill length: %d", len);
        return false;
    }
    if (sys_le16_to_cpu(nth16->wHeaderLength) != sizeof(nth16_t))
    {
        LOG_ERR("  ill nth16 length: %d", sys_le16_to_cpu(nth16->wHeaderLength));
        return false;
    }
    if (sys_le32_to_cpu(nth16->dwSignature) != NTH16_SIGNATURE)
    {
        LOG_ERR("  ill signature: 0x%08x", (unsigned)sys_le32_to_cpu(nth16->dwSignature));
        return false;
    }
    if (len < sizeof(nth16_t) + sizeof(ndp16_t) + 2*sizeof(ndp16_datagram_t))
    {
        LOG_ERR("  ill min len: %d", len);
        return false;
    }
    if (sys_le16_to_cpu(nth16->wBlockLength) > len)
    {
        LOG_ERR("  ill block length: %d > %d", sys_le16_to_cpu(nth16->wBlockLength), len);
        return false;
    }
    if (sys_le16_to_cpu(nth16->wBlockLength) > CONFIG_CDC_NCM_RCV_NTB_MAX_SIZE)
    {
        LOG_ERR("  ill block length2: %d > %d", sys_le16_to_cpu(nth16->wBlockLength), CONFIG_CDC_NCM_RCV_NTB_MAX_SIZE);
        return false;
    }
    if (sys_le16_to_cpu(nth16->wNdpIndex) < sizeof(nth16)  ||  sys_le16_to_cpu(nth16->wNdpIndex) > len - (sizeof(ndp16_t) + 2*sizeof(ndp16_datagram_t)))
    {
        LOG_ERR("  ill position of first ndp: %d (%d)", sys_le16_to_cpu(nth16->wNdpIndex), len);
        return false;
    }

    //
    // check (first) NDP(16)
    //
    const ndp16_t *ndp16 = (const ndp16_t *)(ntb->data + sys_le16_to_cpu(nth16->wNdpIndex));

    if (sys_le16_to_cpu(ndp16->wLength) < sizeof(ndp16_t) + 2*sizeof(ndp16_datagram_t))
    {
        LOG_ERR("  ill ndp16 length: %d", sys_le16_to_cpu(ndp16->wLength));
        return false;
    }
    if (sys_le32_to_cpu(ndp16->dwSignature) != NDP16_SIGNATURE_NCM0  &&  sys_le32_to_cpu(ndp16->dwSignature) != NDP16_SIGNATURE_NCM1)
    {
        LOG_ERR("  ill signature: 0x%08x", (unsigned)sys_le32_to_cpu(ndp16->dwSignature));
        return false;
    }
    if (sys_le16_to_cpu(ndp16->wNextNdpIndex) != 0)
    {
        LOG_ERR("  cannot handle wNextNdpIndex!=0 (%d)", sys_le16_to_cpu(ndp16->wNextNdpIndex));
        return false;
    }

    const ndp16_datagram_t *ndp16_datagram = (const ndp16_datagram_t *)(ntb->data + sys_le16_to_cpu(nth16->wNdpIndex) + sizeof(ndp16_t));
    int ndx = 0;
    uint16_t max_ndx = (uint16_t)((sys_le16_to_cpu(ndp16->wLength) - sizeof(ndp16_t)) / sizeof(ndp16_datagram_t));

    if (max_ndx > 2)
    {
        // number of datagrams in NTB > 1
        LOG_ERR("<<xyx %d (%d)", max_ndx - 1, sys_le16_to_cpu(ntb->nth.wBlockLength));
    }
    if (sys_le16_to_cpu(ndp16_datagram[max_ndx-1].wDatagramIndex) != 0  ||  sys_le16_to_cpu(ndp16_datagram[max_ndx-1].wDatagramLength) != 0)
    {
        LOG_DBG("  max_ndx != 0");
        return false;
    }
    while (sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramIndex) != 0  &&  sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramLength) != 0)
    {
        LOG_DBG("  << %d %d", sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramIndex), sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramLength));
        if (sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramIndex) > len)
        {
            LOG_ERR("(EE) ill start of datagram[%d]: %d (%d)", ndx, sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramIndex), len);
            return false;
        }
        if (sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramIndex) + sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramLength) > len)
        {
            LOG_ERR("(EE) ill end of datagram[%d]: %d (%d)", ndx,
                    sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramIndex) + sys_le16_to_cpu(ndp16_datagram[ndx].wDatagramLength), len);
            return false;
        }
        ++ndx;
    }

#ifdef DEBUG_OUT_ENABLED
    for (uint32_t i = 0;  i < len;  ++i)
    {
        DEBUG_OUT(" %02x", ntb->data[i]);
    }
    DEBUG_OUT("\n");
#endif

    // -> ntb contains a valid packet structure
    //    ok... I did not check for garbage within the datagram indices...
    return true;
}   // recv_validate_datagram



static void recv_transfer_datagram_to_netusb(bool debug)
/**
 * Transfer the next (pending) datagram to netusb and return receive buffer if empty.
 */
{
    bool ok = true;

    //LOG_DBG("");

    {
        const ndp16_datagram_t *ndp16_datagram = (ndp16_datagram_t *)(ncm_interface.recv_usbdrv_ntb.data
                                                                    + sys_le16_to_cpu(ncm_interface.recv_usbdrv_ntb.nth.wNdpIndex)
                                                                    + sizeof(ndp16_t));
        uint16_t datagramIndex  = sys_le16_to_cpu(ndp16_datagram[0].wDatagramIndex);
        uint16_t datagramLength = sys_le16_to_cpu(ndp16_datagram[0].wDatagramLength);
        struct net_pkt *pkt;

        LOG_DBG("  recv - %d %d", datagramIndex, datagramLength);

        NET_ASSERT(datagramIndex != 0  &&  datagramLength != 0);

        if (ok)
        {
            pkt = net_pkt_rx_alloc_with_buffer(netusb_net_iface(), datagramLength, AF_UNSPEC, 0, K_FOREVER);
            if (pkt == NULL)
            {
                LOG_ERR("no memory for network packet");
                ok = false;
            }
        }

        if (ok)
        {
            if (debug)
            {
                printk("->netusb  %d %d\n", datagramIndex, datagramLength);
            }
            if (net_pkt_write(pkt, ncm_interface.recv_usbdrv_ntb.data + datagramIndex, datagramLength)) {
                LOG_ERR("Unable to write into pkt");
                net_pkt_unref(pkt);
                ok = false;
            }
        }

        if (ok)
        {
            netusb_recv(pkt);
        }
    }
}   // recv_transfer_datagram_to_netusb


//-----------------------------------------------------------------------------


static void ncm_init(void)
/**
 * Initialize the driver data structures.
 * Might be called several times.
 */
{
    LOG_DBG("init data structures");

    memset( &ncm_interface, 0, sizeof(ncm_interface));
}   // ncm_init



static uint8_t ncm_get_first_iface_number(void)
{
    return cdc_ncm_cfg.if0.bInterfaceNumber;
}   // ncm_get_first_iface_number



static int ncm_class_handler(struct usb_setup_packet *setup, int32_t *len, uint8_t **data)
/**
 * Class handler.
 * Called for messages with \a USB_REQTYPE_TYPE_CLASS
 */
{
    LOG_WRN("class - len %d req_type 0x%x req 0x%x enabled %u",
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
}   // ncm_class_handler



static int ncm_custom_handler(struct usb_setup_packet *setup, int32_t *len,
                              uint8_t **data)
{
    LOG_WRN("custom - len %d req_type 0x%x req 0x%x enabled %u",
        *len, setup->bmRequestType, setup->bRequest,
        netusb_enabled());

    return -EINVAL;
}   // ncm_custom_handler



static int ncm_vendor_handler(struct usb_setup_packet *setup, int32_t *len,
                              uint8_t **data)
{
    LOG_WRN("vendor - len %d req_type 0x%x req 0x%x enabled %u",
        *len, setup->bmRequestType, setup->bRequest,
        netusb_enabled());

    return -EINVAL;
}   // ncm_vendor_handler



static int ncm_send(struct net_pkt *pkt)
/**
 * Transmit \a pkt.
 * This is called by the netusb layer to initiate a transfer in usbdrv.
 */
{
    size_t size;
    int ret = -EINVAL;
    static int cnt;
    bool debug = false;
    static bool locked;

//    uint32_t lck = irq_lock();

    if (locked)
    {
        LOG_ERR("ncm_send locked!");
        return -ENOBUFS;
    }
    locked = true;

    ++cnt;
    if (cnt > 5000)
    {
        cnt = 0;
        debug = true;
    }

    size = net_pkt_get_len(pkt);

    LOG_DBG("size %d", size);

    NET_ASSERT(size > 10);
    NET_ASSERT(size <= CONFIG_CDC_NCM_RCV_NTB_MAX_SIZE - (sizeof(nth16_t) + sizeof(ndp16_t) + 2*sizeof(ndp16_datagram_t)));

    xmit_setup_next_usbdrv_ntb();

    {
        // -> everything is fine
        xmit_ntb_t *ntb = &ncm_interface.xmit_usbdrv_ntb;

        // copy new datagram to the end of the current NTB
        if (net_pkt_read(pkt, ntb->data + sys_le16_to_cpu(ntb->nth.wBlockLength), size))
        {
            LOG_ERR("ENOBUS");
            locked = false;
            return -ENOBUFS;
        }

        // correct NTB internals
        ntb->ndp_datagram[0].wDatagramIndex  = ntb->nth.wBlockLength;
        ntb->ndp_datagram[0].wDatagramLength = sys_le16_to_cpu(size);

        ntb->nth.wBlockLength = sys_cpu_to_le16(sys_le16_to_cpu(ntb->nth.wBlockLength) + (uint16_t)size);  //  + XMIT_ALIGN_OFFSET(size));

        NET_ASSERT(sys_le16_to_cpu(ntb->nth.wBlockLength) <= CONFIG_CDC_NCM_RCV_NTB_MAX_SIZE);

        ret = 0;
    }

#if 0
    {
        static xmit_ntb_t last_ntb;
        int len = sys_le16_to_cpu(ncm_interface.xmit_usbdrv_ntb.nth.wBlockLength) - sizeof(nth16_t);

        if (memcmp( &last_ntb.ndp, &ncm_interface.xmit_usbdrv_ntb.ndp, len) == 0)
        {
            LOG_WRN("duplicate paket");
        }
        memcpy( &last_ntb, &ncm_interface.xmit_usbdrv_ntb, sys_le16_to_cpu(ncm_interface.xmit_usbdrv_ntb.nth.wBlockLength));
    }
#endif

    {
        int len = sys_le16_to_cpu(ncm_interface.xmit_usbdrv_ntb.nth.wBlockLength);

        if (debug)
        {
            printk("send ");
            for (int i = 0;  i < len;  ++i)
            {
                printk(" %02x", ncm_interface.xmit_usbdrv_ntb.data[i]);
            }
            printk("\n");
        }

        LOG_DBG("  kick off transmission: %d", len);
        int r = usb_transfer_sync(ncm_ep_data[NCM_IN_EP_IDX].ep_addr,
                                  ncm_interface.xmit_usbdrv_ntb.data, len,
                                  USB_TRANS_WRITE | USB_TRANS_NO_ZLP);
        if (r != len)
        {
            LOG_ERR("  cannot start transmission: %d", r);
            locked = false;
            return -EINVAL;
        }
        k_msleep(1);

        xmit_insert_required_zlp(len);
    }

//    irq_unlock(lck);
    locked = false;
    return ret;
}   // ncm_send



static void ncm_read_cb(uint8_t ep, int xferred_bytes, void *priv)
/**
 * new NTB received
 * - make the NTB valid
 * - if ready transfer datagrams to netusb for further processing
 * - if there is a free receive buffer, initiate reception
 */
{
    static int cnt;
    bool debug = false;

    usb_cancel_transfer(ep);

    LOG_DBG("ep:0x%02x size:%d", ep, xferred_bytes);

//    uint32_t lck = irq_lock();

    ++cnt;
    if (cnt > 5000)
    {
        cnt = 0;
        debug = true;
    }

    if (debug)
    {
        printk("read_cb ");
        for (int i = 0;  i < xferred_bytes;  ++i)
        {
            printk(" %02x", ncm_interface.recv_usbdrv_ntb.data[i]);
        }
        printk("\n");
    }

    if (xferred_bytes <= 0)
    {
        LOG_DBG("startup or ZLP received");
    }
    else if ( !recv_validate_datagram( &ncm_interface.recv_usbdrv_ntb, xferred_bytes))
    {
        // verification failed: ignore NTB and return it to free
        LOG_ERR("VALIDATION FAILED. WHAT CAN WE DO IN THIS CASE?  len:%d", xferred_bytes);
        for (int i = 0;  i < xferred_bytes;  ++i)
        {
            printk(" %02x", ncm_interface.recv_usbdrv_ntb.data[i]);
        }
        printk("\n");
    }
    else
    {
        recv_transfer_datagram_to_netusb(debug);
    }

    recv_start_new_reception(ep);

//    irq_unlock(lck);
}   // ncm_read_cb



static int ncm_connect(bool connected)
/**
 * Callback for connection status.
 */
{
    LOG_WRN("connect - %d", connected);

    if (connected)
    {
        // Init packet reception
        ncm_read_cb(ncm_ep_data[NCM_OUT_EP_IDX].ep_addr, 0, NULL);
    }
    else
    {
        // Cancel any transfer
        usb_cancel_transfer(ncm_ep_data[NCM_OUT_EP_IDX].ep_addr);
        usb_cancel_transfer(ncm_ep_data[NCM_IN_EP_IDX].ep_addr);
    }

    return 0;
}   // ncm_connect



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

        ncm_notify_speed_change.header.wIndex = ncm_get_first_iface_number();
        usb_transfer(ep, (uint8_t *)&ncm_notify_speed_change, sizeof(ncm_notify_speed_change),
                     USB_TRANS_WRITE,
                     ncm_status_interface_cb, NULL);
    }
    else if (ncm_interface.if_state == IF_STATE_SPEED_SENT)
    {
        ncm_interface.if_state = IF_STATE_DONE;

        ncm_notify_connected.header.wIndex = ncm_get_first_iface_number();
        usb_transfer(ep, (uint8_t *)&ncm_notify_connected, sizeof(ncm_notify_connected),
                     USB_TRANS_WRITE,
                     ncm_status_interface_cb, NULL);
    }
}   // ncm_status_interface_cb



static void ncm_status_interface(const uint8_t *desc)
/**
 * Check interface activation.
 */
{
    const struct usb_if_descriptor *if_desc = (void *)desc;
    uint8_t iface_num = if_desc->bInterfaceNumber;
    uint8_t alt_set = if_desc->bAlternateSetting;

    LOG_DBG("iface %u alt_set %u", iface_num, if_desc->bAlternateSetting);

    if (iface_num == ncm_get_first_iface_number() + 1)
    {
        ncm_interface.itf_data_alt = alt_set;
    }

    /* First interface is CDC Comm interface */
    if (iface_num != ncm_get_first_iface_number() + 1  ||  alt_set == 0)
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

    netusb_enable(&ncm_function);
    ncm_status_interface_cb(ncm_ep_data[NCM_INT_EP_IDX].ep_addr, 0, NULL);
}   // ncm_status_interface



static void ncm_status_cb(struct usb_cfg_data *cfg,
                          enum usb_dc_status_code status,
                          const uint8_t *param)
{
    ARG_UNUSED(cfg);

    /* Check the USB status and do needed action if required */
    switch (status) {
        case USB_DC_DISCONNECTED:
            LOG_DBG("USB_DC_DISCONNECTED");
            netusb_disable();
            break;

        case USB_DC_INTERFACE:
            LOG_DBG("USB_DC_INTERFACE");
            ncm_status_interface(param);
            break;

        case USB_DC_RESET:
            LOG_DBG("USB_DC_RESET");
            ncm_init();
            break;

        case USB_DC_ERROR:
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

    LOG_DBG("iface: %d", bInterfaceNumber);

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

    ncm_init();
}   // ncm_interface_config



USBD_DEFINE_CFG_DATA(cdc_ncm_config) = {
    .usb_device_description = NULL,                                  // ok
    .interface_config = ncm_interface_config,                        // ok
    .interface_descriptor = &cdc_ncm_cfg.if0,                        // ok
    .cb_usb_status = ncm_status_cb,
    .interface = {
        .class_handler = ncm_class_handler,
        .custom_handler = ncm_custom_handler,
        .vendor_handler = ncm_vendor_handler,
    },
    .num_endpoints = ARRAY_SIZE(ncm_ep_data),
    .endpoint = ncm_ep_data,
};
