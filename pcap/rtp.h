#ifndef RTP_H
#define RTP_H

#include "common.h"

#ifndef MUTEX
#define MUTEX pthread_mutex_t
#endif

#ifndef SOCKET
#define SOCKET int
#endif

#ifndef SOCKADDR_IN
#define SOCKADDR_IN struct sockaddr_in
#endif

#ifndef SOCKADDR
#define SOCKADDR struct sockaddr
#endif


#define MAX_RTP_TRAN_SIZE 		1200
#define MAX_VIDEO_FRAME_SIZE		409600
#define MAX_AUDIO_FRAME_SIZE		102400

typedef struct _frame_t
{
	uint32_t    frame_type; // 1-I, 2-P
	size_t i_frame_size;
	uint8_t* p_frame;
	uint64_t i_time_stamp;
	int i_flag;
	int i_pktseq;

	struct _frame_t* p_next;
} frame_t;

typedef struct _rtp_header_t
{
	uint8_t i_version;
	uint8_t i_extend;
	uint8_t i_m_tag;
	uint8_t i_cc;
	uint8_t i_pt;
	uint32_t i_seq_num;
	uint32_t i_timestamp;
	uint32_t i_ssrc;
	uint32_t i_csrc;

	uint8_t i_nalu_header;
} rtp_header_t;

typedef struct _rtp_s
{
	uint32_t i_nalu_ok_flag;
	uint32_t i_last_pkt_num;
	uint32_t    frame_type; // 1-I, 2-P
	uint16_t i_seq_num; // 序列号
	FILE* h264file;
	MUTEX mutex;

} rtp_s;


enum { kH264NALHeaderLengthInBytes = 1,
	kH264FUAHeaderLengthInBytes = 2,
	kH264FUANALUType            = 28,
	kH264NALU_SEI               = 6,
	kH264NALU_SPS               = 7,
	kH264NALU_PPS               = 8,
	kH264NALU_IDR               = 5};

int rtp_init(rtp_s* p_rtp);
int rtp_deinit(rtp_s* p_rtp);

int get_rtp_header(rtp_header_t* p_header, uint8_t* p_buf);


int RtpTo264(unsigned char* buffer, int recv_bytes, unsigned char* save_buffer, uint32_t* pnNALUOkFlag, uint32_t* pnLastPkt,int offset,uint32_t* frametype);
void writeFrame(frame_t *frame,frame_t *prev_frame ,rtp_s* p_rtp ,bool& find_next_idr);


#define PVOID void*
typedef PVOID THREAD(PVOID Arg);
pthread_t threadCreate(THREAD* funcThread, void* param);
int video_process(uint8_t *buff,rtp_s* p_rtp,int size);
void* readThread(void* arg);
void* writeThread(void* arg);
#endif
