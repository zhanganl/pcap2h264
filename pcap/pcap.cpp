//
//  pcap.c
//  pcap
//
//  Created by 喻军 on 2016/12/8.
//  Copyright © 2016年 喻军. All rights reserved.
//
#include <netinet/in.h>
#include <stdio.h>
#include "pcap.h"

void prinfPcapFileHeader(pcap_file_header *pfh){
	if (pfh==NULL) {
		return;
	}
	printf("=====================\n"
			"magic:0x%0x\n"
			"version_major:%u\n"
			"version_minor:%u\n"
			"thiszone:%d\n"
			"sigfigs:%u\n"
			"snaplen:%u\n"
			"linktype:%u\n"
			"=====================\n",
			pfh->magic,
			pfh->version_major,
			pfh->version_minor,
			pfh->thiszone,
			pfh->sigfigs,
			pfh->snaplen,
			pfh->linktype);
}

void printfPcapHeader(pcap_header *ph){
	if (ph==NULL) {
		return;
	}
	printf("=====================\n"
			"ts.timestamp_s:%u\n"
			"ts.timestamp_ms:%u\n"
			"capture_len:%u\n"
			"len:%d\n"
			"=====================\n",
			ph->ts.timestamp_s,
			ph->ts.timestamp_ms,
			ph->capture_len,
			ph->len);


}

void printPcap(void * data,size_t size){
	unsigned  short iPos = 0;
	//int * p = (int *)data;
	//unsigned short* p = (unsigned short *)data;
	if (data==NULL) {
		return;
	}

	//printf("\n==data:0x%x,len:%lu=========",data,size);

	for (iPos=0; iPos < size/sizeof(unsigned short); iPos++) {
		//printf(" %x ",(int)( * (p+iPos) ));
		//unsigned short a = ntohs(p[iPos]);

		unsigned short a = ntohs( *((unsigned short *)data + iPos ) );
		if (iPos%8==0) printf("\n");
		if (iPos%4==0) printf(" ");

		printf("%04x",a);


	}

}
