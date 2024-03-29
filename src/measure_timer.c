#include "measure_timer.h"
#include "measure_log.h"
#include "myHashSet.h"





// pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

//定时器需要执行的动作
//测试定时器，每隔一段时间打印一次当前时间
void* print_current_time(void* argv){
    //获取参数，即定时时间
    int count = 0;
    int time_val = ((timer_param_t*)argv)->time_val;

    MyHashSet *recv_Set = ((timer_param_t*)argv)->recv_Set;
    ElasticSketch *recv_sketch = ((timer_param_t*)argv)->recv_sketch;
    pthread_mutex_t* recv_mutex = ((timer_param_t*)argv)->recv_mutex;
    
    MyHashSet *send_Set = ((timer_param_t*)argv)->send_Set;
    ElasticSketch *send_sketch = ((timer_param_t*)argv)->send_sketch;
    pthread_mutex_t* send_mutex = ((timer_param_t*)argv)->send_mutex;

    int sock = ((timer_param_t*)argv)->sock;
    // int type = ((timer_param_t*)argv)->type;

    // sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));  //每个字节都用0填充
    serv_addr.sin_family = AF_INET;  //使用IPv4地址
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    serv_addr.sin_port = htons(12345);  //端口
    connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    printf("connect done");

    MYSQL *conn_ptr;
    unsigned int timeout = 600;	//超时时间7秒
    int ret = 0;
    conn_ptr = mysql_init(NULL);//初始化
	if(!conn_ptr)
	{
		printf("mysql_init failed!\n");
		//return -1;
	}

	ret = mysql_options(conn_ptr,MYSQL_OPT_CONNECT_TIMEOUT,(const char*)&timeout);//设置超时选项
	if(ret)
	{
		printf("Options Set ERRO!\n");
	}
	conn_ptr = mysql_real_connect(conn_ptr,"127.0.0.1","root","123456","mytestdb",3306,NULL,0);//连接MySQL testdb数据库
	if(conn_ptr)
	{
		printf("Connection Succeed!\n");
	}
	else	//错误处理
	{
		printf("Connection Failed!\n");
		if(mysql_errno(conn_ptr))
		{
			printf("Connect Erro:%d %s\n",mysql_errno(conn_ptr),mysql_error(conn_ptr));//返回错误代码、错误消息
		}
		//return -2;
	}
    char query[100] = "truncate table measure";
    mysql_real_query(conn_ptr,"truncate table measure",strlen(query));
    char query2[100] = "truncate table total";
    mysql_real_query(conn_ptr,"truncate table total",strlen(query2));
    char query3[100] = "truncate table total_send";
    mysql_real_query(conn_ptr,"truncate table total_send",strlen(query3));
    char query4[100] = "truncate table total_recv";
    mysql_real_query(conn_ptr,"truncate table total_recv",strlen(query4));
    printf("have clear table measure, total in mytestdb\n");
    char buf[ 1024 ];
    getcwd(buf, 1024);
    printf("\n");
    printf("%s\n", buf);
    printf("\n");


    time_t now;
    struct tm* timenow;
    //清空文件
    FILE *fp, *fp2;
    fp = fopen(STATISTICS_LOG_FILE_RECV,"wb+");
    fp2 = fopen(STATISTICS_LOG_FILE_SEND,"wb+");
    fprintf(fp,"=====================================================================\n");
    fprintf(fp2,"===================================================================\n");

    fclose(fp);
    fclose(fp2);




    while(1){ 
        printf("\nmeasurement module is running, statistics will be saved in /measure_log/statistics_log.txt\n");
        count += 1;
        sleep(time_val);
        time(&now);
        timenow = gmtime(&now);
        //睡眠
        pthread_mutex_lock(send_mutex);  
        save_flow_statistics(count, send_sketch, send_Set, conn_ptr, 0);
        pthread_mutex_unlock(send_mutex);

        pthread_mutex_lock(recv_mutex);  
        save_flow_statistics(count, recv_sketch, recv_Set, conn_ptr, 1);
        pthread_mutex_unlock(recv_mutex);
        //printf("have save once");
    }


}

//创建并启动定时器线程
// void measure_timer_create(int time_val,MyHashSet *Set, ElasticSketch *sketch,pthread_mutex_t* mutex,int sock, int type){
//     pthread_t measure_timer_thread;

//     timer_param.time_val = time_val;
//     timer_param.Set = Set;
//     timer_param.sketch = sketch;
//     timer_param.mutex = mutex;
//     timer_param.sock = sock;
//     timer_param.type = type;
    
//     pthread_create(&measure_timer_thread,NULL,print_current_time,&timer_param);
// }


void measure_timer_create(  int time_val,
                            MyHashSet *recv_Set, ElasticSketch *recv_sketch,pthread_mutex_t* recv_mutex,
                            MyHashSet *send_Set, ElasticSketch *send_sketch,pthread_mutex_t* send_mutex,
                            int sock){
    pthread_t measure_timer_thread;

    timer_param.time_val = time_val;
    timer_param.sock = sock;

    timer_param.recv_Set = recv_Set;
    timer_param.recv_sketch = recv_sketch;
    timer_param.recv_mutex = recv_mutex;

    timer_param.send_Set = send_Set;
    timer_param.send_sketch = send_sketch;
    timer_param.send_mutex = send_mutex;

    // timer_param.recv_type = type;
    
    pthread_create(&measure_timer_thread,NULL,print_current_time,&timer_param);
}
