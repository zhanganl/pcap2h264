#include "rtp.h"
#include "pcap.h"
#include <map>
#include <time.h>

#ifdef MACOS
#include <sys/_types/_timespec.h>
#else
#include <string.h>
#endif


#define MAX_ETH_FRAME 1514

#define BUFSIZE 4096

#ifdef TARGET_OS_MAC
#define H264_FILE "/Users/ucpaas/zhanganl/test_cap/test_cap_liphone.h264"
#define PCAP_FILE "/Users/ucpaas/zhanganl/test_cap/liphone.pcap"
#else
char H264_FILE[1024];
char PCAP_FILE[1024];
#endif
std::map<int32_t,frame_t*>  m_packet;

bool fileend=false;
static bool insequence(frame_t* frame,frame_t* prev_frame)
{
	if(frame->i_pktseq==prev_frame->i_pktseq+1)
		return true;
	else
		return false;
}

static bool isIDR(frame_t* frame)
{
	if(frame->frame_type==1)
		return true;
	else
		return false;
}

void* readThread(void* arg)
{
	rtp_s* input=(rtp_s*)arg;

	pcap_file_header  pfh;
	pcap_header  ph;
	int count=0;
	unsigned char * buff = NULL;
	size_t readSize=0;
	int ret = 0;

	FILE *fp = fopen(PCAP_FILE, "rw");

	if (fp==NULL) {
		fprintf(stderr, "Open file %s error.",PCAP_FILE);
		//ret = ERROR_FILE_OPEN_FAILED;
		exit(INPUTFILEERR);
	}


	fread(&pfh, sizeof(pcap_file_header), 1, fp);
	 prinfPcapFileHeader(&pfh);

	buff = (unsigned char *)malloc(MAX_ETH_FRAME);
	for (count=1; ; count++) {
		memset(buff,0,MAX_ETH_FRAME);
		//read pcap header to get a packet
		//get only a pcap head count .
		readSize=fread(&ph, sizeof(pcap_header), 1, fp);
		if (readSize<=0) {
			fileend=true;
			break;
		}
        printfPcapHeader(&ph);

		if (buff==NULL) {
			fprintf(stderr, "malloc memory failed.\n");
			ret = ERROR_MEM_ALLOC_FAILED;
			exit(ret);
		}

		readSize=fread(buff,1,ph.capture_len, fp);
		if (readSize != ph.capture_len) {
			free(buff);
			fprintf(stderr, "pcap file parse error.\n");
			ret = ERROR_PCAP_PARSE_FAILED;
			exit(ret);
		}
		video_process(buff+IPUDPLEN,input,ph.capture_len-IPUDPLEN);

		if (feof(fp) || readSize <=0 ) {
			fileend=true;
			break;
		}
	}

ERROR:
	//free
	if (buff) {
		free(buff);
		buff=NULL;
	}
	if (fp) {
		fclose(fp);
		fp=NULL;
	}

	return NULL;
}

void writeFrame(frame_t *frame,frame_t *prev_frame ,rtp_s* p_rtp ,bool& find_next_idr)
{
	std::map<int32_t,frame_t*>::iterator itr;

	itr=m_packet.begin();;
	frame=itr->second;

	if(prev_frame!=NULL&&find_next_idr==false)
	{
		if(insequence(frame,prev_frame)==false)
			find_next_idr=true;
	}
	if(find_next_idr==true)
	{
		if(isIDR(frame)==true)
		{
			find_next_idr=false;
		}
		else
		{

			free(frame->p_frame);

			free(prev_frame);
			pthread_mutex_lock(&p_rtp->mutex);

			m_packet.erase(itr);

			pthread_mutex_unlock(&p_rtp->mutex);
			prev_frame=frame;

			return;
		}

	}

	size_t len=frame->i_frame_size;
	uint8_t* buf=frame->p_frame;
	fwrite(buf,len,1,p_rtp->h264file);
	fflush(p_rtp->h264file);
	free(frame->p_frame);
	free(prev_frame);
	pthread_mutex_lock(&p_rtp->mutex);

	m_packet.erase(itr);

	pthread_mutex_unlock(&p_rtp->mutex);
	prev_frame=frame;
}


void* writeThread(void* arg)
{
	rtp_s* p_rtp = (rtp_s*) arg;
	if (p_rtp == NULL)
	{
		printf("ERROR!\n");
		return NULL;
	}
	timespec time;
	time.tv_sec=0;
	time.tv_nsec=1000000;
	std::map<int32_t,frame_t*>::iterator itr;
	frame_t* prev_frame=NULL;
	frame_t* frame=NULL;
	bool find_next_idr=false;
	while(1)
	{
		while (m_packet.size()<100) {

			if(fileend==true)
				break;

			nanosleep(&time,NULL);
		}

		if(fileend==true)
			break;

		writeFrame(frame,prev_frame,p_rtp,find_next_idr);

	}
	while (m_packet.size()!=0) {
		writeFrame(frame,prev_frame,p_rtp,find_next_idr);
	}
	free(frame);
	return NULL;
}





pthread_t threadCreate(THREAD* funcThread, void* param)
{
	pthread_attr_t attr;
	pthread_t Thrd;
	struct sched_param SchedParam;
	pthread_attr_init(&attr);
	//  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
	//  sched_getparam(0, &SchedParam);
	SchedParam.sched_priority = sched_get_priority_max(SCHED_FIFO);
	pthread_attr_setschedparam(&attr, &SchedParam);

	int s = pthread_create(&Thrd, &attr, funcThread, param);
	if (s != 0)
	{
		printf("threadCreate failed.\n");
		exit(THREADERR);
		//handle_error_en(s, "pthread_create");
	}

	return Thrd;
}

int rtp_init(rtp_s* p_rtp)
{
	int i_ret = 0;
	if (p_rtp == NULL)
	{
		i_ret = -1;
	}
	else
	{
		p_rtp->i_nalu_ok_flag = 0;
		p_rtp->i_last_pkt_num = 0;
		p_rtp->i_seq_num = 0;
		p_rtp->h264file=fopen(H264_FILE,"wb");
		if(p_rtp->h264file==NULL)
			exit(OUTFILEERR);
		pthread_mutex_init(&p_rtp->mutex, NULL);


	}
	return i_ret;
}

int rtp_deinit(rtp_s* p_rtp)
{
	int i_ret = 0;

	if (p_rtp == NULL)
	{
		i_ret = -1;
	}

	return i_ret;
}

int video_process(uint8_t *buff,rtp_s* p_rtp,int size)
{
	int i_time_out = 0;
	const int rtpheader_len=12;
	int offset=rtpheader_len;
	if (p_rtp == NULL)
	{
		return 0;
	}

	i_time_out = 0;
	rtp_header_t rtp_header;

	get_rtp_header(&rtp_header, buff);
	if (rtp_header.i_pt == 96)
	{
		//检查有多少贡献源
		if(rtp_header.i_cc!=0)
		{
			offset+=rtp_header.i_cc*4;
		}
		if(rtp_header.i_extend==1)
		{

			const uint8_t *extensionData = &buff[offset];
			size_t extensionLength = 4 * (extensionData[2] << 8 | extensionData[3]);

			offset += (4 + extensionLength);
		}

		if(size<offset)
			return -1;

		uint32_t frametype=0;
		frame_t *frame=(frame_t*)malloc(sizeof(frame_t));
		frame->p_frame=(unsigned char*)malloc(BUFSIZE);
		memset(frame->p_frame, 0, BUFSIZE);

		size_t i_size = RtpTo264(buff, size, frame->p_frame, &p_rtp->i_nalu_ok_flag, &p_rtp->i_last_pkt_num,offset,&frametype);

		frame->i_pktseq=p_rtp->i_last_pkt_num;
		frame->i_frame_size=i_size;
		frame->frame_type=frametype;
		frame->i_time_stamp=rtp_header.i_timestamp;
		pthread_mutex_lock(&p_rtp->mutex);

		m_packet.insert(std::make_pair(frame->i_pktseq,frame));
		pthread_mutex_unlock(&p_rtp->mutex);
	}
	return 0;
}

int get_rtp_header(rtp_header_t* p_header, uint8_t* p_buf)
{
	int i_ret = 0;

	if (p_header == NULL || p_buf == NULL )
	{
		i_ret = -1;
	}
	else
	{
		p_header->i_version = (p_buf[0] & 0xC0) >> 6;
		p_header->i_extend = (p_buf[0] & 0x10) >> 4;
		p_header->i_cc = (p_buf[0] & 0x0F);
		p_header->i_m_tag = (p_buf[1] & 0x80) >> 7;
		p_header->i_pt = (p_buf[1] & 0x7F);
		p_header->i_seq_num = (p_buf[2] << 8);
		p_header->i_seq_num += p_buf[3];
		p_header->i_timestamp = (p_buf[4] << 24);
		p_header->i_timestamp += (p_buf[5] << 16);
		p_header->i_timestamp += (p_buf[6] << 8);
		p_header->i_timestamp += p_buf[7];

		p_header->i_ssrc = (p_buf[8] << 24);
		p_header->i_ssrc += (p_buf[9] << 16);
		p_header->i_ssrc += (p_buf[10] << 8);
		p_header->i_ssrc += p_buf[11];

		//p_header->i_csrc = (p_buf[12] << 24);
		//p_header->i_csrc += (p_buf[13] << 16);
		//p_header->i_csrc += (p_buf[14] << 8);
		//p_header->i_csrc += p_buf[15];

		i_ret = 12;
		return i_ret;
	}
	return i_ret;
}

int RtpTo264(unsigned char* buffer, int recv_bytes,unsigned char* save_buffer, uint32_t* pnNALUOkFlag, uint32_t* pnLastPkt,int offset,uint32_t* frametype)
{
	unsigned char original_nal_type;
	unsigned int FU_FLAG = 0;
	unsigned int MARK_BIT = 0;
	unsigned char NAL_HEAD = 0;
	int save_len = 0;
	unsigned int nPkt = 0;
	unsigned char* h264buf=buffer+offset;
	nPkt = (unsigned int) (((buffer[2]) << 8) | (buffer[3]));

	if (nPkt - (*pnLastPkt) > 1)
	{
		*pnNALUOkFlag = 0;
	}

	(*pnLastPkt) = nPkt;
	FU_FLAG = (h264buf[0])&(0x1C);

	if (kH264FUANALUType == FU_FLAG)//如果是FU型分割
	{

		original_nal_type = h264buf[1] & 0x1F;
		if(original_nal_type==kH264NALU_IDR)
			*frametype=1;
		else
			*frametype=2;

		MARK_BIT = (buffer[1]) >> 7; //取第二个字节的最高位，以便判断是否是此NALU的最后一包
		if ((*pnNALUOkFlag) == 0)//这是当前NALU的第一包
		{

			NAL_HEAD = ((h264buf[0])&(0xE0)) | ((h264buf[1])&(0x1F)); //取第13个字节的高3位和第14字节的低5位，拼成此NALU的头
			save_buffer[3] = 1;
			save_buffer[4] = NAL_HEAD; //将NALU的头保存起来

			memcpy(&(save_buffer[5]), &(h264buf[2]), recv_bytes - offset -2); //从第15字节开始就是NALU的数据部分，保存起来
			save_len = recv_bytes - offset -2 +4+1; //减12字节的RTP头，减2字节FU头，加4字节的起始码，加1字节的NALU头
			*pnNALUOkFlag = 1; //这是当前NALU的第一包，接下来的就不是第一包了。
		}
		else
		{
			if ((recv_bytes - offset -2 ) > 4096)
			{
			}
			else if ((recv_bytes - offset -2 ) <= 0)
			{
			}
			else
			{
				memcpy(save_buffer, h264buf + 2, recv_bytes - offset - 2); //不是NALU的第一包，直接从第15字节保存起来
				save_len = recv_bytes - offset -2 ; //减12字节的RTP头，减2字节FU头
			}
		}
		if (MARK_BIT == 1)//这是此NALU的最后一包
		{
			*pnNALUOkFlag = 0; //这一NALU已经收齐，下面再来的包就是下一个NALU的了
		}
	}
	else //不是FU型分割，即一个NALU就是一包
	{

		if(original_nal_type==kH264NALU_SPS||original_nal_type==kH264NALU_PPS||original_nal_type==kH264NALU_SEI||original_nal_type==kH264NALU_IDR)
			*frametype=1;
		else
			*frametype=2;

		save_buffer[3] = 1;
		memcpy(&(save_buffer[4]), h264buf, recv_bytes - offset); //第offset+1字节是此NALU的头，offset+2字节及以后是NALU的内容，一起保存
		save_len = recv_bytes - offset + 4; //减offset字节的RTP头
		*pnNALUOkFlag = 0; //一个NALU就是一包，下面再来的包就是下一个NALU的了

	}

	return save_len; //save_buffer里面要保存多少字节的数据
}











