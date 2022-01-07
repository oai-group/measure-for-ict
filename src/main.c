#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#include "measure_log.h"

//创建下行表
MyHashSet recvSet;
//创建上行表
MyHashSet sendSet;

pthread_mutex_t recv_mutex;
pthread_mutex_t send_mutex;

ElasticSketch recv_elastic_sketch;
ElasticSketch send_elastic_sketch;

int sock;


int main()
{

   //数据的初始化
    // curr_eNB_id = 101;
    pthread_mutex_t recv_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;
    Init_ElasticSketch(&recv_elastic_sketch, BUCKET_NUM, LIGHT_PART_COUNTER_NUM);
    initHashSet(myHashCodeString, myEqualString, &recvSet);
    //这是发送给流识别模块的sock
    sock = socket(AF_INET, SOCK_STREAM, 0);
    Init_ElasticSketch(&send_elastic_sketch, BUCKET_NUM, LIGHT_PART_COUNTER_NUM);
    initHashSet(myHashCodeString, myEqualString, &sendSet);
    measure_timer_create(5, &recvSet, &recv_elastic_sketch,&recv_mutex,
                        &sendSet, &send_elastic_sketch,&send_mutex,
                        sock);
    
    
    //创建接受数据的udp socket对象
    int sockfd=socket(AF_INET,SOCK_DGRAM,0);

    //创建网络通信对象
    struct sockaddr_in addr;
    addr.sin_family =AF_INET;
    addr.sin_port =htons(50000);
    addr.sin_addr.s_addr=inet_addr("127.0.0.1");

    //绑定socket对象与通信链接
    int ret =bind(sockfd,(struct sockaddr*)&addr,sizeof(addr));
    if(0>ret)
    {
        printf("bind\n");
        return -1;

    }
    struct sockaddr_in cli;
    socklen_t len=sizeof(cli);

    uint8_t buffer[256];

    while(1)
    {
        bzero(buffer, sizeof(buffer));

        int recv_len = recvfrom(sockfd, buffer,sizeof(buffer),0,(struct sockaddr*)&cli,&len);

        printf("recv length =%d\n",recv_len);

        ///解析程序，解析出五元组，长度，时间等信息
        udp_data_parser udp_data;
        uint8_t flag = udp_measure_parser(buffer, &udp_data);
        // 出错
        if (flag != 1) {
            printf("error!!");
            continue;
        }


        uint8_t flow_key[13]={'0'}; // 存五元组
        struct timespec nowtime;
        memset(&nowtime,0,sizeof(struct timespec));
        uint16_t length;
        char direction;

        // 正常f赋值
        memcpy(flow_key, &(udp_data.five_tuple), 13);
        nowtime = udp_data.current_time;
        length = udp_data.five_tuple.packet_len;
        direction = udp_data.direction;

        //如果是上行，则加入send表
        if(direction == 1){
        pthread_mutex_lock(&send_mutex);
        measure_packet_by_udp_data(&sendSet,
                                    sock,
                                    &send_elastic_sketch,
                                    &flow_key,
                                    &nowtime,
                                    length);
        pthread_mutex_unlock(&send_mutex);    
        }else if (direction == 2)
        {
            pthread_mutex_lock(&recv_mutex);
            measure_packet_by_udp_data(&recvSet,
                                    sock,
                                    &recv_elastic_sketch,
                                    &flow_key,
                                    &nowtime,
                                    length);
            pthread_mutex_unlock(&recv_mutex);
        }else{
            continue;
        }
        // buf =66;
        // sendto(sockfd,&buf,sizeof(buf),0,(struct sockaddr*)&cli,len);

    }
    close(sockfd);

}