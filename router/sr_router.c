/**********************************************************************
* file: sr_router.c
* date: Mon Feb 18 12:50:42 PST 2002
* Contact: casado@stanford.edu
*
* Description:
*
* This file contains all the functions that interact directly
* with the routing table, as well as the main entry method
* for routing.
*
**********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
* Method: sr_init(void)
* Scope: Global
*
* Initialize the routing subsystem
*
*---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

void sr_handlearp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
        sr_arp_hdr_t *arp_hdr, *arp_reply_hdr = 0;
        sr_ethernet_hdr_t *ether_hdr, *received_ether_hdr, *queuing_ether = 0;
        uint8_t *reply_packet = 0;
        struct sr_if *iface = 0;
        struct sr_arpreq *arpreq = 0;
        struct sr_packet *queuing_packet = 0;
		size_t reply_packet_size = 0;
        
        /* check if header has the correct size */
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
                fprintf(stderr, "Error: invalid ARP header length\n");
                return;
        }
        
        arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        
        /* check if ARP hardware type is ethernet */
        if (arp_hdr->ar_hrd != htons(arp_hrd_ethernet)) {
                fprintf(stderr, "Error: unknown ARP hardware format\n");
                return;
        }
        
        /* check if arp protocol type is ip */
        if (arp_hdr->ar_pro != htons(ethertype_ip)) {
                fprintf(stderr, "Error: unknown ARP protocol format\n");
                return;
        }
        
        /* grab the receiving interface */
        if ((iface = sr_get_interface(sr, interface)) == 0) {
                fprintf(stderr, "Error: interface does not exist (sr_handlearp)\n");
                return;
        }
        
        /* handle received ARP request */
        if (arp_hdr->ar_op == htons(arp_op_request)) {
                
                /* create new reply packet */
				reply_packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
				
                if ((reply_packet = malloc(reply_packet_size)) == NULL) {
                        fprintf(stderr,"Error: out of memory (sr_handlearp)\n");
                        return;
                }
				
                /* construct ARP header */
                arp_reply_hdr = (sr_arp_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));
                arp_reply_hdr->ar_hrd = htons(arp_hrd_ethernet); /* format of hardware address */
                arp_reply_hdr->ar_pro = htons(ethertype_ip);                 /* format of protocol address */
                arp_reply_hdr->ar_hln = ETHER_ADDR_LEN;         /* length of hardware address */
                arp_reply_hdr->ar_pln = 4;                                 /* length of protocol address */
                arp_reply_hdr->ar_op = htons(arp_op_reply);         /* ARP opcode (command) */
				
				fprintf(stderr, "TEST:Our MAC is: %X:%X:%X:%X:%X:%X\n", iface->addr[0],iface->addr[1],iface->addr[2],iface->addr[3],iface->addr[4],iface->addr[5]);
                memcpy(arp_reply_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);                                 /* sender hardware address */
				fprintf(stderr, "TEST:reply packet has source MAC: %X:%X:%X:%X:%X:%X\n", arp_reply_hdr->ar_sha[0],arp_reply_hdr->ar_sha[1],arp_reply_hdr->ar_sha[2],arp_reply_hdr->ar_sha[3],arp_reply_hdr->ar_sha[4],arp_reply_hdr->ar_sha[5]);
                arp_reply_hdr->ar_sip = iface->ip;                                 /* sender IP address */
                memcpy(arp_reply_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);                                         /* target hardware address */
                arp_reply_hdr->ar_tip = arp_hdr->ar_sip;                                 /* target IP address */
                
                /* construct ethernet header */
                ether_hdr = (sr_ethernet_hdr_t*)reply_packet;
				received_ether_hdr = (sr_ethernet_hdr_t*)packet;
                memcpy(ether_hdr->ether_dhost, received_ether_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
                ether_hdr->ether_type = htons(ethertype_arp);
                
                /* send the packet */
                if (sr_send_packet(sr, reply_packet, reply_packet_size, (const char*)interface) == -1) {
                        fprintf(stderr, "Error: sending packet failed (sr_handlearp)\n");
                }
                free(reply_packet);
        }
        
        /* handle received ARP reply */
        else if (arp_hdr->ar_op == htons(arp_op_reply)) {
        
                /* check if the target ip matches ours */
                if (arp_hdr->ar_tha != iface->addr) {
                        fprintf(stderr, "Error: ARP reply does not match our MAC (sr_handlearp)\n");
                        return;
                }
        
                /* check if the target ip matches ours */
                if (arp_hdr->ar_tip != htonl(iface->ip)) {
                    fprintf(stderr, "Error: ARP reply does not match our ip (sr_handlearp)\n");
                    return;
                }
                
                /* check if the ip is already in our cache */
                if (sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_sip) != NULL) {
                        fprintf(stderr, "Error: ARP reply ip already in cache (sr_handlearp)\n");
                        return;
                }
                
                /* Insert the reply to our ARP cache and grab the list of packets waiting for this IP */
                if ((arpreq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip)) != NULL) {
                
                        queuing_packet = arpreq->packets;
                        
                        /* loop through all queuing packets */
                        while(queuing_packet != NULL) {
                        
                                /* fill in the MAC field */
                                queuing_ether = (sr_ethernet_hdr_t *)(queuing_packet->buf);
                                memcpy(queuing_ether->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                                
                                /* send the queuing packet */
                                if (sr_send_packet(sr, queuing_packet->buf, queuing_packet->len, (const char*)queuing_packet->iface) == -1) {
                                        fprintf(stderr, "Error: sending queuing packet failed (sr_handlearp)\n");
                                }
                                
                                queuing_packet = queuing_packet->next;
                        }
                        
                        /* destroy the request queue */
                        sr_arpreq_destroy(&(sr->cache), arpreq);
                }
        }
}


uint8_t* sr_generate_icmp(sr_ethernet_hdr_t *received_ether_hdr,
                          sr_ip_hdr_t *received_ip_hdr,
                          struct sr_if *iface,
                          uint8_t type, uint8_t code)
{
	uint8_t *reply_packet = 0;
	sr_icmp_echo_hdr_t *icmp_hdr, *recv_icmp_hdr = 0;
	sr_ip_hdr_t *ip_hdr = 0;
	sr_ethernet_hdr_t *ether_hdr = 0;
	size_t icmp_size = 0;
	int ret = 0;
	
	/* type 0 echo reply */
	if (type == 0) {
		
		fprintf(stderr,"TEST: generating echo reply\n");
		
		/* create new reply packet */
		if ((reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_echo_hdr_t))) == NULL) {
				fprintf(stderr,"Error: out of memory (sr_generate_icmp)\n");
				return 0;
		}
		
		/* construct ICMP header */
		icmp_hdr = (sr_icmp_echo_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_echo_hdr_t));
		recv_icmp_hdr = (sr_icmp_echo_hdr_t *)(received_ip_hdr + sizeof(sr_ip_hdr_t));
		memcpy(icmp_hdr, recv_icmp_hdr, sizeof(sr_icmp_echo_hdr_t));
		fprintf(stderr,"TEST: bytes copied: %d\n", sizeof(sr_icmp_echo_hdr_t));
		icmp_hdr->icmp_type = type;
		icmp_hdr->icmp_code = code;
		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_echo_hdr_t));
		
		/* grab the size of ICMP header */
		icmp_size = sizeof(sr_icmp_echo_hdr_t);
	}
	/* Destination net unreachable (type 3, code 0) OR Time exceeded (type 11, code 0),
	 since the two types use the exact same struct, except the next_mtu field which is unused for type 11 */
	else if (type == 3 || type == 11) {
	
		fprintf(stderr,"TEST: generating icmp type 3 or 11 with code %d\n", code);
	
		sr_icmp_t3_hdr_t* icmp_hdr;
		
		/* create new reply packet */
		if ((reply_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t))) == NULL) {
			fprintf(stderr,"Error: out of memory (sr_generate_icmp)\n");
			return 0;
		}
		
		/* construct ICMP header */
		icmp_hdr = (sr_icmp_t3_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_hdr->icmp_type = type;
		icmp_hdr->icmp_code = code;
		icmp_hdr->unused = 0;
		icmp_hdr->next_mtu = 0;                
		if (type == 3) {        /* only set next_mtu if ICMP type is 3*/
				icmp_hdr->next_mtu = 1500;
		}
		memcpy(icmp_hdr->data, received_ip_hdr, ICMP_DATA_SIZE);
		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
		
		/* grab the size of ICMP header */
		icmp_size = sizeof(sr_icmp_t3_hdr_t);
	}
	/* An ICMP type that we can't handle */
	else {
		fprintf(stderr,"Error: unsupported ICMP type (sr_generate_icmp)\n");
		return 0;
	}
	
	/* construct IP header */
	ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_hl = 5;                                                                        /* header length */
	ip_hdr->ip_v = 4;                                                                        /* version */
	ip_hdr->ip_tos = 0;                                                                       /* type of service */
	fprintf(stderr,"TEST: ip head length: %d, icmp head length: %d\n",sizeof(sr_ip_hdr_t),icmp_size);
	ip_hdr->ip_len = htons(20 + icmp_size);                                                /* total length */
	ip_hdr->ip_id = 0;                                                                        /* identification */
	ip_hdr->ip_off = htons(IP_DF);                                                                /* fragment offset field */
	ip_hdr->ip_ttl = INIT_TTL;                                                        /* time to live */
	ip_hdr->ip_p = ip_protocol_icmp;                                                /* protocol */
	ip_hdr->ip_src = iface->ip;                                                        /* source ip address */
	ip_hdr->ip_dst = received_ip_hdr->ip_src;                                        /* dest ip address */
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, 20);                /* checksum */
	
	/* construct ethernet header */
	ether_hdr = (sr_ethernet_hdr_t*)reply_packet;
	memcpy(ether_hdr->ether_dhost, received_ether_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
	ether_hdr->ether_type = htons(ethertype_ip);
					
	return reply_packet;
}


void sr_handleip(struct sr_instance* sr,
				 uint8_t * packet/* lent */,
				 unsigned int len,
				 char* interface/* lent */)
{
	sr_ip_hdr_t *ip_hdr = 0;
	struct sr_if *recv_iface, *dst_iface = 0;
	sr_icmp_hdr_t *icmp_hdr = 0;
	uint8_t *reply_packet = 0;
	struct sr_rt *rt = 0;
	uint32_t nexthop_ip, longest_mask = 0;
	struct sr_arpentry *arp_entry = 0;
	struct sr_arpreq *arp_req = 0;
	sr_ethernet_hdr_t *ether_hdr = 0;
	int matched = 0;
	size_t reply_packet_size = 0;
	
	/* check if header has the correct size */
	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
		fprintf(stderr, "Error: invalid IP header length\n");
		return;
	}
	
	ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	
	/* perform IP header checksum */
	fprintf(stderr, "TEST: the checksum is: %X\n", cksum(ip_hdr, (ip_hdr->ip_hl * 4)));
	if (cksum(ip_hdr, (ip_hdr->ip_hl * 4)) != 0xffff) {
		fprintf(stderr, "Error: IP checksum failed\n");
		return;
	}
	
	/* grab the receiving interface */
	if ((recv_iface = sr_get_interface(sr, interface)) == 0) {
		fprintf(stderr, "Error: interface does not exist (sr_handleip)\n");
		return;
	}
	
	fprintf(stderr, "TEST:IP packet from IP: %u\n", ip_hdr->ip_src);
	fprintf(stderr, "TEST:IP packet to IP: %u\n", ip_hdr->ip_dst);
	fprintf(stderr, "TEST:IP packet received from interface: %s\n", interface);
	
	/* Loop through all interfaces to check if packet is destined to one of our IPs */
	dst_iface = sr->if_list;
	
	while (dst_iface) {
	
		/* found destination interface */
		if (ip_hdr->ip_dst == dst_iface->ip) {
			fprintf(stderr, "TEST:one interface with ip: %d\n", dst_iface->ip);
			break;
		}
		dst_iface = dst_iface->next;
	}
		
	/* if the packet is destined to our ip */
	if (ip_hdr->ip_dst == dst_iface->ip) {
		
		fprintf(stderr, "TEST: IP Packet for us\n");
	
		/* if it is an ICMP */
		if (ip_hdr->ip_p == ip_protocol_icmp) {
		
			fprintf(stderr, "TEST: It is a ICMP\n");
				
			/* check if header has the correct size */
			if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
				fprintf(stderr, "Error: invalid ICMP header length\n");
				return;
			}
			
			icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			
			/* if it is an ICMP echo request, send an ICMP echo reply */
			if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
				
				fprintf(stderr, "TEST: It is a echo request(ping)\n");
				
				/* perform ICMP header checksum */
				if (cksum(icmp_hdr, (len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))) != 0xffff) {
					fprintf(stderr, "Error: ICMP checksum failed\n");
					return;
				}
				
				/* generate an echo reply packet */
				if ((reply_packet = sr_generate_icmp((sr_ethernet_hdr_t *)packet, ip_hdr, dst_iface, 0, 0)) == 0) {
					fprintf(stderr, "Error: failed to generate ICMP echo reply packet\n");
					return;
				}
				
				reply_packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
				
				/* send an ICMP echo reply */
				if (sr_send_packet(sr, reply_packet, reply_packet_size + ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4, (const char*)(dst_iface->name)) == -1) {
					fprintf(stderr, "Error: sending packet failed (sr_handleip)\n");
				}
				
				free(reply_packet);                                
			}
		}
		/* if it contains a TCP or UDP payload */
		else {
		
				/* generate Destination net unreachable (type 3, code 0) reply packet */
				if ((reply_packet = sr_generate_icmp((sr_ethernet_hdr_t *)packet, ip_hdr, recv_iface, 3, 3)) == 0) {
						fprintf(stderr, "Error: failed to generate ICMP packet\n");
						return;
				}
				
				reply_packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
				
				/* send an ICMP */
				if (sr_send_packet(sr, reply_packet, reply_packet_size, (const char*)interface) == -1) {
						fprintf(stderr, "Error: sending packet failed (sr_handleip)\n");
				}
				
				free(reply_packet);                
		}
	}
	/* packet not for us, forward it */
	else {
			
			/* if TTL reaches 0 */
			if (ip_hdr->ip_ttl <= htons(1)) {
			
					/* generate Time exceeded (type 11, code 0) reply packet */
					if ((reply_packet = sr_generate_icmp((sr_ethernet_hdr_t *)packet, ip_hdr, recv_iface, 11, 0)) == 0) {
							fprintf(stderr, "Error: failed to generate ICMP packet\n");
							return;
					}
					
					reply_packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
					
					/* send an ICMP */
					if (sr_send_packet(sr, reply_packet, reply_packet_size, (const char*)interface) == -1) {
							fprintf(stderr, "Error: sending packet failed (sr_handleip)\n");
					}
					
					free(reply_packet);
			}
			/* if packet has enough TTL */
			else {
					
					/* decrement the TTL by 1 */
					ip_hdr->ip_ttl --;
					
					/* recompute the packet checksum */
					ip_hdr->ip_sum = 0;
					ip_hdr->ip_sum = cksum(ip_hdr, (5 * 4));
					
					/* Find entry in the routing table with the longest prefix match */
					rt = sr->routing_table;
					while (rt != NULL) {
							
							/* update the gateway ip and the longest mask so far */
							if ((rt->dest.s_addr & rt->mask.s_addr) == (ntohl(ip_hdr->ip_dst) & rt->mask.s_addr) &&
									rt->mask.s_addr > longest_mask) {
									nexthop_ip = rt->gw.s_addr;
									longest_mask = rt->mask.s_addr;
									matched = 1;
							}
							
							rt = rt->next;
					}
					
					/* if a matching routing table entry was NOT found */
					if (matched == 0) {
							
							/* generate Destination net unreachable (type 3, code 0) reply packet */
							if ((reply_packet = sr_generate_icmp((sr_ethernet_hdr_t *)packet, ip_hdr, recv_iface, 3, 0)) == 0) {
									fprintf(stderr, "Error: failed to generate ICMP packet\n");
									return;
							}
							
							reply_packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
							
							/* send an ICMP */
							if (sr_send_packet(sr, reply_packet, reply_packet_size, (const char*)interface) == -1) {
									fprintf(stderr, "Error: sending packet failed (sr_handleip)\n");
							}
							
							free(reply_packet);
					}
					/* if a matching routing table entry was found */
					else {
							/* if the next hop is 0.0.0.0 */
							if(nexthop_ip == 0) {
									nexthop_ip = ip_hdr->ip_dst;
							}
							
							/* set the source MAC of ethernet header */
							ether_hdr = (sr_ethernet_hdr_t*)packet;
							memcpy(ether_hdr->ether_shost, recv_iface->addr, ETHER_ADDR_LEN);
							
							/* if the next-hop IP CANNOT be found in ARP cache */
							if ((arp_entry = sr_arpcache_lookup(&(sr->cache), htonl(nexthop_ip))) == NULL) {
									
									/* send an ARP request */
									arp_req = sr_arpcache_queuereq(&(sr->cache), nexthop_ip, packet, len, interface);
									handle_arpreq(sr, arp_req);
							}
							/* if the next-hop IP can be found in ARP cache */
							else {									
								/* set the destination MAC of ethernet header */
								memcpy(ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
								
								/* send the packet */
								if (sr_send_packet(sr, packet, len, (const char*)interface) == -1) {
										fprintf(stderr, "Error: sending packet failed (sr_handleip)\n");
								}							
								free(arp_entry);
							}
					}
			}
	}
}

/*---------------------------------------------------------------------
* Method: sr_handlepacket(uint8_t* p,char* interface)
* Scope: Global
*
* This method is called each time the router receives a packet on the
* interface. The packet buffer, the packet length and the receiving
* interface are passed in as parameters. The packet is complete with
* ethernet headers.
*
* Note: Both the packet buffer and the character's memory are handled
* by sr_vns_comm.c that means do NOT delete either. Make a copy of the
* packet instead if you intend to keep it around beyond the scope of
* the method call.
*
*---------------------------------------------------------------------*/
 
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  
  /* check if header has the correct size */
  if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Error: invalid packet length (ether_hdr)\n");
        return;
  }
  
  if (len > 1500) {
        fprintf(stderr, "Error: packet length longer than MTU(ether_hdr)");
        return;
  }
  
  switch (ethertype(packet)) {
  
        /* ------------- Handling ARP -------------------- */
        case ethertype_arp:
			fprintf(stderr, "TEST: ARP packet with type: %X\n", ethertype(packet));
            sr_handlearp(sr, packet, len, interface);
            break;

        /* ------------- Handling IP -------------------- */
        case ethertype_ip:
			fprintf(stderr, "TEST: IP packet with type: %X\n", ethertype(packet));
            sr_handleip(sr, packet, len, interface);
            break;

        default:
            fprintf(stderr, "Unknown ether_type: %d\n", ethertype(packet));
            break;

  }/* -- switch -- */
  

}/* end sr_ForwardPacket */