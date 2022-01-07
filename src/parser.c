/*
 * @Descripttion: 
 * @version: 
 * @Author: smallchaochao
 * @Date: 2021-12-28 15:12:59
 * @LastEditors: smallchaochao
 * @LastEditTime: 2021-12-29 15:35:36
 */
// #include "measure/parser.h"
#include "parser.h"

//从PDCP_IND报文中提取IP头部信息，存储到IP_header结构体中
//考虑字节序，高于8位的，需要使用htons或者htonl进行转换
int IP_header_parser(char* packet, IP_header_t* header){
    // if (packet == NULL || header == NULL){
    //     return -1;
    // }
    header->version = (uint8_t)(packet[VERSION_AND_HEADER_LEN_OFFSET] >> 4);
    header->header_len = (uint8_t)((packet[VERSION_AND_HEADER_LEN_OFFSET] & 0x0F)<<2);
    header->DS_field = (uint8_t)(packet[DS_FIELD_OFFSET]);
    header->total_len = (uint16_t)(htons(*((uint16_t*) &(packet[TOTAL_LEN_OFFSET]))));
    header->identification = (uint16_t)(htons(*((uint16_t*) &(packet[IDENTIFICATION_OFFSET]))));
    header->flags = (uint8_t)((htons(*((uint16_t*) &(packet[FLAGS_AND_FRAGMENT_OFFSET_OFFSET])))) >> 13);
    header->fragment_offset = (uint16_t)((htons(*((uint16_t*) &(packet[FLAGS_AND_FRAGMENT_OFFSET_OFFSET])))) & 0x1FFF);
    header->ttl = (uint8_t)(packet[TTL_OFFSET]);
    header->protocol = (uint8_t)(packet[PROTOCOL_OFFSET]);
    header->header_checksum = (uint16_t)(htons(*((uint16_t*) &(packet[HEADER_CHECKSUM_OFFSET]))));
    header->src_ip = (uint32_t)(htonl(*((uint32_t*) &(packet[SRC_IP_OFFSET]))));
    header->dst_ip = (uint32_t)(htonl(*((uint32_t*) &(packet[DST_IP_OFFSET]))));

    return 0;
}


int trans_header_parser(char* packet, trans_header_t* header){
    // if (packet == NULL || header == NULL){
    //     return -1;
    // }

    header->src_port = (uint16_t)(htons(*((uint16_t*) &(packet[SRC_PORT_OFFSET]))));
    header->dst_port = (uint16_t)(htons(*((uint16_t*) &(packet[DST_PORT_OFFSET]))));

    return 0;
}

//仅仅处理ipv4的包
int extract_packet_key(char* packet, packet_key_t* key){
    IP_header_t ip_header;
    trans_header_t trans_header;

    IP_header_parser(packet,&ip_header);
    trans_header_parser(packet,&trans_header);

    if (ip_header.version == IP_VERSION_4){

        key->src_ip = ip_header.src_ip;
        key->dst_ip = ip_header.dst_ip;
        key->protocol = ip_header.protocol;
        key->src_port = trans_header.src_port;
        key->dst_port = trans_header.dst_port;

        // key->packet_len = ip_header.total_len;
        if(ip_header.protocol == TCP_PROTOCOL_NUM){
            key->packet_len = ip_header.total_len;
            uint16_t tcp_header_len = (uint8_t)((packet[TCP_HEADER_LEN_OFFSET] >> 2) & 0x3C);
            //printf("\ntcphl  %d  %d  %d\n", tcp_header_len, ip_header.header_len, ip_header.total_len);
            
            key->packet_len = ip_header.total_len - ip_header.header_len - tcp_header_len;
        }
        else if(ip_header.protocol == UDP_PROTOCOL_NUM){
            key->packet_len = ip_header.total_len - ip_header.header_len - UDP_HEADER_LEN;
        }
        else
            key->packet_len = ip_header.total_len;

        return 0;
    }

    return -1;
}

//将packet_key存入一个13字节的数组
void packet_key_to_char(packet_key_t* key, uint8_t* five_tuple){
    // *((uint32_t*) &(five_tuple[0])) = htonl(key->src_ip);
    // *((uint32_t*) &(five_tuple[4])) = htonl(key->dst_ip);
    // *((uint16_t*) &(five_tuple[8])) = htons(key->src_port);
    // *((uint16_t*) &(five_tuple[10])) = htons(key->dst_port);
    // *((uint8_t*) &(five_tuple[12])) = key->protocol;
    *((uint32_t*) &(five_tuple[0])) = htonl(key->src_ip);
    *((uint32_t*) &(five_tuple[4])) = htonl(key->dst_ip);
    *((uint16_t*) &(five_tuple[8])) = htons(key->src_port);
    *((uint16_t*) &(five_tuple[10])) = htons(key->dst_port);
    *((uint8_t*) &(five_tuple[12])) = key->protocol;

}


// 解析数据包
uint8_t udp_measure_parser(uint8_t* buffer, udp_data_parser* udp_data) {
    int OFFSET = 12;
    udp_data->direction = (uint8_t)(buffer[OFFSET]);
    // 解析 源ip
    udp_data->five_tuple.src_ip = (uint32_t)(htonl(*((uint32_t*) &(buffer[OFFSET + 1]))));
    // 解析 目的ip
    udp_data->five_tuple.dst_ip = (uint32_t)(htonl(*((uint32_t*) &(buffer[OFFSET + 5]))));
    // 解析 协议类型
    udp_data->five_tuple.protocol = (uint8_t)(buffer[OFFSET + 9]);
    // 解析 源端口
    udp_data->five_tuple.src_port = (uint16_t)(htons(*((uint16_t*) &(buffer[OFFSET + 10]))));
    // 解析 目的端口
    udp_data->five_tuple.dst_port = (uint16_t)(htons(*((uint16_t*) &(buffer[OFFSET + 12]))));
    // 解析 数据长度
    // udp_data->five_tuple.packet_len = (uint16_t)(htons(*((uint16_t*) &(buffer[OFFSET + 14]))));
    udp_data->five_tuple.packet_len = *((uint16_t*) &(buffer[OFFSET + 14]));
    // 解析 时间戳 秒
    // udp_data->current_time.tv_sec = (uint64_t)(htonll(*((uint64_t*) &(buffer[OFFSET + 16]))));
    udp_data->current_time.tv_sec = *((uint64_t*) &(buffer[OFFSET + 16]));
    // 解析 时间戳 纳秒
    // udp_data->current_time.tv_nsec = (uint64_t)(htonll(*((uint64_t*) &(buffer[OFFSET + 24]))));
    udp_data->current_time.tv_nsec = *((uint64_t*) &(buffer[OFFSET + 24]));

    printf("udp_data->five_tuple.dst_port: %u\n", udp_data->five_tuple.dst_port);
    printf("udp_data->five_tuple.packet_len: %u\n", udp_data->five_tuple.packet_len);
    printf("*((uint16_t*) &(buffer[OFFSET + 14])): %u\n", *((uint16_t*) &(buffer[OFFSET + 14])));
    printf("udp_data->current_time.tv_sec: %lu\n", udp_data->current_time.tv_sec);
    printf("*((uint64_t*) &(buffer[OFFSET + 16])): %lu\n", *((uint64_t*) &(buffer[OFFSET + 16])));
    printf("udp_data->current_time.tv_nsec: %lu\n", udp_data->current_time.tv_nsec);

    // for(int i=0;i<48;i++){
    //     printf("%x \n", buffer[i]);
    // }

    return 1;   // success
}


// 64位转换
unsigned long htonll(unsigned long val)
{

    return (((unsigned long)htonl((unsigned int)((val << 32) >> 32))) << 32) | 
            (unsigned long)htonl((unsigned int)(val >> 32));

}