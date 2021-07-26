//
// Created by ubuntu on ২২/৭/২১.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "headers.h"


unsigned short calculate_checksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nLeft = length;
    int sum = 0;
    unsigned short temp=0;

    /***********************
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
    ************************/
    while (nLeft > 1)  {
        sum += *w++;
        nLeft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nLeft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short)(~sum);
}


void send_packet(struct IPHeader* ip)
{
    /***********************
     * Step 1: Create a raw network socket.
     * AF_INET -> socket can communicate with IPv4 addresses
     * SOCK_RAW -> no TCP/IP processing, no link level headers
     * IPPROTO_RAW -> directly edit header & payload of IP packet
    ************************/
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock < 0){
        printf("Error in creating new socket\n");
    }

    /************************
     * Step 2: Set socket option.
     * When IP_HDRINCL is enabled on the socket, the packet must contain an IP header.
     * Without this option, the kernel's IP header will be used.
     ************************/
    int enable = 1;
    int setOptionStatus = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    if(setOptionStatus < 0){
        printf("Error in setting socket option\n");
    }

    /************************
     * Step 3: Set the destination address for the socket.
     ************************/
    struct sockaddr_in destination;
    destination.sin_family = AF_INET;
    destination.sin_port = htons(80);
    destination.sin_addr = ip->destination_address;

    /************************
     * Step 4: Send the packet on the socket.
     ************************/
    int sendStatus =  sendto(sock, ip, ntohs(ip->total_length), 0, (struct sockaddr *)&destination, sizeof(destination));

    if(sendStatus < 0){
        printf("Error in sending packet %d\n", errno);
    }
    close(sock);
}



int main(int argc, char *argv[]) {
    char buffer[100000];

    if(argc < 3){
        printf("Invalid number of arguments\n");
        printf("Please follow this format : ./out_file_name source_address destination_address\n");
        exit(1);
    }

    char source_address[strlen(argv[1])];
    strcpy(source_address, argv[1]);
    char destination_address[strlen(argv[2])];
    strcpy(destination_address, argv[2]);

    memset(buffer, 0, 100000); // fill buffer with 0

    char data[80000]; // payload of ip packet
    for (int i = 0; i < 80000; i++) {
        data[i] = 'A';
    }
    strcpy(buffer + sizeof(struct ICMPHeader) + sizeof(struct IPHeader), data);


    // build icmp header
    struct ICMPHeader *icmp = (struct ICMPHeader *) (buffer + sizeof(struct IPHeader));
    icmp->type = 8; // ICMP Type: 8 -> request, 0 -> reply.
    icmp->checksum = 0;
    icmp->checksum = calculate_checksum((unsigned short *) icmp, sizeof(struct ICMPHeader) + strlen(data));


    // build ip header
    struct IPHeader *ip = (struct IPHeader *) buffer;
    ip->version = 4;
    ip->ip_header_length = 5;
    ip->time_to_live = 64;
    ip->source_address.s_addr = inet_addr(source_address);
    ip->destination_address.s_addr = inet_addr(destination_address);
    ip->protocol = IPPROTO_ICMP;
    unsigned long len = sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + strlen(data);
    ip->total_length = htons(len);


    // send the large packet in fragments
    if (len < MTU) {
        send_packet(ip);
    } else {
        int allowable_data_length = MTU - (sizeof(struct IPHeader) + sizeof(struct ICMPHeader));
        allowable_data_length = (allowable_data_length / 8) * 8;
        int actual_data_length = len - (sizeof(struct IPHeader) + sizeof(struct ICMPHeader));
        int offset = 0;
        int id = 100; // one id for all fragments

        while (actual_data_length > 0) {
            char fragment_buffer[MTU];
            memset(fragment_buffer, 0, MTU);

            char fragment_data[allowable_data_length + 1];
            for (int i = 0; i < allowable_data_length; i++) {
                fragment_data[i] = data[i + offset];
            }
            fragment_data[allowable_data_length] = '\0';

            strcpy(fragment_buffer + sizeof(struct ICMPHeader) + sizeof(struct IPHeader), fragment_data);

            struct ICMPHeader *fragment_icmp = (struct ICMPHeader *) (fragment_buffer + sizeof(struct IPHeader));
            fragment_icmp->type = 8;
            fragment_icmp->checksum = 0;
            fragment_icmp->checksum = calculate_checksum((unsigned short *) fragment_icmp, sizeof(struct ICMPHeader) + strlen(fragment_data));

            struct IPHeader *fragment = (struct IPHeader *) fragment_buffer;
            fragment->version = 4;
            fragment->identification = htons(id);
            fragment->ip_header_length = 5;
            fragment->time_to_live = 64;
            fragment->source_address.s_addr = inet_addr(source_address);
            fragment->destination_address.s_addr = inet_addr(destination_address);
            fragment->protocol = IPPROTO_ICMP;

            fragment->fragment = 0;
            if (actual_data_length > MTU) {
                fragment->fragment = MORE_FRAGMENTS;
            }
            fragment->fragment += offset / 8;
            offset += allowable_data_length;
            actual_data_length -= allowable_data_length;
            unsigned long fragment_len = sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + strlen(fragment_data);
            fragment->total_length = htons(fragment_len);
            send_packet(fragment);
            printf("Fragment sent of size %lu\n", fragment_len);
        }
    }

    return 0;
}
