//
//  main.c
//  pcap
//
//  Created by 喻军 on 2016/12/8.
//  Copyright © 2016年 喻军. All rights reserved.
//

#include <memory.h>
#include <arpa/inet.h>
#include "pcap.h"
#include "stdlib.h"
#include "rtp.h"


#define MAX_ETH_FRAME 1514

#ifndef TARGET_OS_MAC
extern char H264_FILE[1024];
extern char PCAP_FILE[1024];

#endif

int main (int argc, const char * argv[])
{
	//  void *thread_result;
#ifndef TARGET_OS_MAC
	if(argc!=3)
	{
		printf("error ,1、 input 2、 output \n");
		return 0;
	}

	memset(PCAP_FILE,0,sizeof(PCAP_FILE));
	memset(H264_FILE,0,sizeof(H264_FILE));

	strcpy(PCAP_FILE, argv[1]);
	strcpy(H264_FILE, argv[2]);

#endif

	rtp_s input;
	rtp_init(&input);

	pthread_t id = threadCreate(writeThread, &input);
	threadCreate(readThread, &input);
	pthread_join(id, NULL);

	return 0;


}
