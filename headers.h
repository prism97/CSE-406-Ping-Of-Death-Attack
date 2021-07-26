//
// Created by ubuntu on ২২/৭/২১.
//
#define MTU 1500
#define MORE_FRAGMENTS 0x2000


struct IPHeader {
    unsigned char         ip_header_length:4;       // 4 bits
    unsigned char         version:4;                // 4 bits
    unsigned char         type_of_service;          // 8 bits
    unsigned short int    total_length;             // 16 bits
    unsigned short int    identification;           // 16 bits
    unsigned short int    fragment;                 // 16 bits
    unsigned char         time_to_live;             // 8 bits
    unsigned char         protocol;                 // 8 bits
    unsigned short int    header_checksum;          // 16 bits
    struct  in_addr       source_address;
    struct  in_addr       destination_address;
};


struct ICMPHeader {
    unsigned char         type;                     // 8 bits
    unsigned char         code;                     // 8 bits
    unsigned short int    checksum;                 // 16 bits
    unsigned short int    identifier;               // 16 bits
    unsigned short int    sequence_number;          // 16 bits
};