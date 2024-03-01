#include "initadapter.h"
#include "logger.h"
#include "../rawsock/rawsock.h"
#include "../rawsock/rawsock-adapter.h"
#include "../stack/stack-arpv4.h"
#include "../stack/stack-ndpv6.h"
#include "../stub/stub-pcap-dlt.h"


/***************************************************************************
 * Initialize the network adapter.
 *
 * This requires finding things like our IP address, MAC address, and router
 * MAC address. The user could configure these things manually instead.
 *
 * Note that we don't update the "static" configuration with the discovered
 * values, but instead return them as the "running" configuration. That's
 * so if we pause and resume a scan, auto discovered values don't get saved
 * in the configuration file.
 ***************************************************************************/
int
initialize_adapter(struct Xconf *xconf)
{
    char *ifname;
    char ifname2[256];
    unsigned adapter_ip = 0;
    unsigned is_usable_ipv4 = !massip_has_ipv4_targets(&xconf->targets); /* I don't understand this line, seems opposite */
    unsigned is_usable_ipv6 = !massip_has_ipv6_targets(&xconf->targets); /* I don't understand this line, seems opposite */
    ipaddress_formatted_t fmt;

    /*
     * ADAPTER/NETWORK-INTERFACE
     *
     * If no network interface was configured, we need to go hunt down
     * the best Interface to use. We do this by choosing the first
     * interface with a "default route" (aka. "gateway") defined
     */
    if (xconf->nic.ifname[0])
        ifname = xconf->nic.ifname;
    else {
        /* no adapter specified, so find a default one */
        int err;
        ifname2[0] = '\0';
        err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
        if (err || ifname2[0] == '\0') {
            LOG(0, "[-] FAIL: could not determine default interface\n");
            LOG(0, "    [hint] try \"--interface ethX\"\n");
            return -1;
        }
        ifname = ifname2;
    }
    LOG(1, "[+] interface = %s\n", ifname);

    /*
     * START ADAPTER
     *
     * Once we've figured out which adapter to use, we now need to
     * turn it on.
     */
    xconf->nic.adapter = rawsock_init_adapter(
                                            ifname,
                                            xconf->is_pfring,
                                            xconf->is_sendq,
                                            xconf->nmap.packet_trace,
                                            xconf->is_offline,
                                            xconf->nic.is_vlan,
                                            xconf->nic.vlan_id);
    if (xconf->nic.adapter == 0) {
        LOG(0, "[-] if:%s:init: failed\n", ifname);
        return -1;
    }
    xconf->nic.link_type = xconf->nic.adapter->link_type;
    LOG(1, "[+] interface-type = %u\n", xconf->nic.link_type);
    rawsock_ignore_transmits(xconf->nic.adapter, ifname);

    /*
     * MAC ADDRESS
     *
     * This is the address we send packets from. It actually doesn't really
     * matter what this address is, but to be a "responsible" citizen we
     * try to use the hardware address in the network card.
     */
    if (xconf->nic.link_type == PCAP_DLT_NULL) {
        LOG(1, "[+] source-mac = %s\n", "none");
    } else if (xconf->nic.link_type == PCAP_DLT_RAW) {
        LOG(1, "[+] source-mac = %s\n", "none");
    } else {
        if (xconf->nic.my_mac_count == 0) {
            if (macaddress_is_zero(xconf->nic.source_mac)) {
                rawsock_get_adapter_mac(ifname, xconf->nic.source_mac.addr);
            }
            /* If still zero, then print error message */
            if (macaddress_is_zero(xconf->nic.source_mac)) {
                fprintf(stderr, "[-] FAIL: failed to detect MAC address of interface:"
                        " \"%s\"\n", ifname);
                fprintf(stderr, " [hint] try something like "
                        "\"--source-mac 00-11-22-33-44-55\"\n");
                return -1;
            }
        }
        
        fmt = macaddress_fmt(xconf->nic.source_mac);
        LOG(1, "[+] source-mac = %s\n", fmt.string);
    }
    

    /*
     * IPv4 ADDRESS
     *
     * We need to figure out that IP address to send packets from. This
     * is done by querying the adapter (or configured by user). If the
     * adapter doesn't have one, then the user must configure one.
     */
    if (massip_has_ipv4_targets(&xconf->targets)) {
        adapter_ip = xconf->nic.src.ipv4.first;
        if (adapter_ip == 0) {
            adapter_ip = rawsock_get_adapter_ip(ifname);
            xconf->nic.src.ipv4.first = adapter_ip;
            xconf->nic.src.ipv4.last = adapter_ip;
            xconf->nic.src.ipv4.range = 1;
        }
        if (adapter_ip == 0) {
            /* We appear to have IPv4 targets, yet we cannot find an adapter
             * to use for those targets. We are having trouble querying the
             * operating system stack. */
            LOG(0, "[-] FAIL: failed to detect IP of interface \"%s\"\n", ifname);
            LOG(0, "    [hint] did you spell the name correctly?\n");
            LOG(0, "    [hint] if it has no IP address, manually set with something like "
                            "\"--source-ip 198.51.100.17\"\n");
            if (massip_has_ipv4_targets(&xconf->targets)) {
                return -1;
            }
        }
        
        fmt = ipv4address_fmt(adapter_ip);
        LOG(1, "[+] source-ip = %s\n", fmt.string);
        
        if (adapter_ip != 0)
            is_usable_ipv4 = 1;
        
        /*
         * ROUTER MAC ADDRESS
         *
         * NOTE: this is one of the least understood aspects of the code. We must
         * send packets to the local router, which means the MAC address (not
         * IP address) of the router.
         *
         * Note: in order to ARP the router, we need to first enable the libpcap
         * code above.
         */
        if (xconf->is_offline) {
            /* If we are doing offline benchmarking/testing, then create
             * a fake MAC address fro the router */
            memcpy(xconf->nic.router_mac_ipv4.addr, "\x66\x55\x44\x33\x22\x11", 6);
        } else if (xconf->nic.link_type == PCAP_DLT_NULL) {
            /* If it's a VPN tunnel, then there is no Ethernet MAC address */
            LOG(1, "[+] router-mac-ipv4 = %s\n", "implicit");
    } else if (xconf->nic.link_type == PCAP_DLT_RAW) {
            /* If it's a VPN tunnel, then there is no Ethernet MAC address */
            LOG(1, "[+] router-mac-ipv4 = %s\n", "implicit");
        } else if (macaddress_is_zero(xconf->nic.router_mac_ipv4)) {
            ipv4address_t router_ipv4 = xconf->nic.router_ip;
            int err = 0;


            LOG(2, "[+] if(%s): looking for default gateway\n", ifname);
            if (router_ipv4 == 0)
                err = rawsock_get_default_gateway(ifname, &router_ipv4);
            if (err == 0) {
                fmt = ipv4address_fmt(router_ipv4);
                LOG(1, "[+] router-ip = %s\n", fmt.string);
                LOG(2, "[+] if(%s):arp: resolving IPv4 address\n", ifname);
                
                stack_arp_resolve(
                        xconf->nic.adapter,
                        adapter_ip,
                        xconf->nic.source_mac,
                        router_ipv4,
                        &xconf->nic.router_mac_ipv4);
            }
            
            fmt = macaddress_fmt(xconf->nic.router_mac_ipv4);
            LOG(1, "[+] router-mac-ipv4 = %s\n", fmt.string);
            if (macaddress_is_zero(xconf->nic.router_mac_ipv4)) {
                fmt = ipv4address_fmt(xconf->nic.router_ip);
                LOG(0, "[-] FAIL: ARP timed-out resolving MAC address for router %s: \"%s\"\n", ifname, fmt.string);
                LOG(0, "    [hint] try \"--router ip 192.0.2.1\" to specify different router\n");
                LOG(0, "    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP\n");
                LOG(0, "    [hint] try \"--interface eth0\" to change interface\n");
                return -1;
            }
        }
    }
        

    /*
     * IPv6 ADDRESS
     *
     * We need to figure out that IPv6 address to send packets from. This
     * is done by querying the adapter (or configured by user). If the
     * adapter doesn't have one, then the user must configure one.
     */
    if (massip_has_ipv6_targets(&xconf->targets)) {
        ipv6address adapter_ipv6 = xconf->nic.src.ipv6.first;
        if (ipv6address_is_zero(adapter_ipv6)) {
            adapter_ipv6 = rawsock_get_adapter_ipv6(ifname);
            xconf->nic.src.ipv6.first = adapter_ipv6;
            xconf->nic.src.ipv6.last = adapter_ipv6;
            xconf->nic.src.ipv6.range = 1;
        }
        if (ipv6address_is_zero(adapter_ipv6)) {
            fprintf(stderr, "[-] FAIL: failed to detect IPv6 address of interface \"%s\"\n",
                            ifname);
            fprintf(stderr, "    [hint] did you spell the name correctly?\n");
            fprintf(stderr, "    [hint] if it has no IP address, manually set with something like "
                            "\"--source-ip 2001:3b8::1234\"\n");
            return -1;
        }
        fmt = ipv6address_fmt(adapter_ipv6);
        LOG(1, "[+] source-ip = [%s]\n", fmt.string);
        is_usable_ipv6 = 1;
        
        /*
         * ROUTER MAC ADDRESS
         */
        if (xconf->is_offline) {
            memcpy(xconf->nic.router_mac_ipv6.addr, "\x66\x55\x44\x33\x22\x11", 6);
        }
        if (macaddress_is_zero(xconf->nic.router_mac_ipv6)) {
            /* [synchronous]
             * Wait for router neighbor notification. This may take
             * some time */
            stack_ndpv6_resolve(
                    xconf->nic.adapter,
                    adapter_ipv6,
                    xconf->nic.source_mac,
                    &xconf->nic.router_mac_ipv6);
        }
        
        fmt = macaddress_fmt(xconf->nic.router_mac_ipv6);
        LOG(1, "[+] router-mac-ipv6 = %s\n", fmt.string);
        if (macaddress_is_zero(xconf->nic.router_mac_ipv6)) {
            fmt = ipv4address_fmt(xconf->nic.router_ip);
            LOG(0, "[-] FAIL: NDP timed-out resolving MAC address for router %s: \"%s\"\n", ifname, fmt.string);
            LOG(0, "    [hint] try \"--router-mac-ipv6 66-55-44-33-22-11\" instead to bypass ARP\n");
            LOG(0, "    [hint] try \"--interface eth0\" to change interface\n");
            return -1;
        }


    }

    /*
     * set NonBlock to avoid block of pcap recv when using bpf filter.
     */
    rawsock_set_nonblock(xconf->nic.adapter);

    xconf->nic.is_usable = (is_usable_ipv4 & is_usable_ipv6);



    LOG(2, "[+] if(%s): initialization done.\n", ifname);
    return 0;
}
