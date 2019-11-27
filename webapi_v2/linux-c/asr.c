#include "asr.h"

// #define SERVER_ADDR "http://openapi.xfyun.cn/v2/aiui"
#define SERVER_ADDR "openapi.xfyun.cn"
#define AIUI_APPID "5d4a580f"
#define AIUI_API_KEY "3d5cb9b3c529cd6aabaf1e058b27cd19"
#define AIUI_AUE "raw"
#define AIUI_AUTH_ID "27853aa9684eb19789b784a89ea5befd"
#define AIUI_DATA_TYPE "audio"
#define AIUI_SAMPLE_RATE "16000"
#define AIUI_SCENE "main"
//#define AIUI_RESULT_LEVEL "complete"
#define AIUI_RESULT_LEVEL "plain"
#define AIUI_LAT "39.938838"
#define AIUI_LNG "116.368624"
#define AIUI_PERS_PARAM = "{\\\"auth_id\\\":\\\"27853aa9684eb19789b784a89ea5befd\\\"}"
//#define AIUI_PARAM "{\"result_level\":\"AIUI_RESULT_LEVEL\",\"auth_id\":\"AIUI_AUTH_ID\",\"data_type\":\"AIUI_DATA_TYPE\",\"sample_rate\":\"AIUI_SAMPLE_RATE\",\"scene\":\"AIUI_SCENE\",\"lat\":\"AIUI_LAT\",\"lng\":\"AIUI_LNG\"}"
#define AIUI_PARAM "{\"result_level\":\"plain\",\"auth_id\":\"27853aa9684eb19789b784a89ea5befd\",\"data_type\":\"audio\",\"sample_rate\":\"16000\",\"scene\":\"main\"}"
//使用个性化参数时参数格式如下：
//param = "{\"result_level\":\""+RESULT_LEVEL+"\",\"auth_id\":\""+AUTH_ID+"\",\"data_type\":\""+DATA_TYPE+"\",\"sample_rate\":\""+SAMPLE_RATE+"\",\"scene\":\""+SCENE+"\",\"lat\":\""+LAT+"\",\"lng\":\""+LNG+"\",\"pers_param\":\""+PERS_PARAM+"\"}"

//X-Param=eyJyZXN1bHRfbGV2ZWwiOiJjb21wbGV0ZSIsImF1dGhfaWQiOiJjODRhYmI3NDE3Y2QzOGJkOWQzNGI0MTBjZTI2ZmFkZSIsImRhdGFfdHlwZSI6ImF1ZGlvIiwic2FtcGxlX3JhdGUiOiIxNjAwMCIsInNjZW5lIjoibWFpbl9ib3giLCJsYXQiOiIzOS45Mzg4MzgiLCJsbmciOiIxMTYuMzY4NjI0In0=
//X-CurTime: 1571012315\r\n
//X-CheckSum: 1ce620b4bb78c059e33bf2dead70b293\r\n
//X-Appid: 5d2f27d2\r\n
static const char __audio2text[] = 
{
"POST /v2/aiui HTTP/1.1\r\n\
Host: openapi.xfyun.cn\r\n\
Connection: keep-alive\r\n\
User-Agent: AIRobotToy/1.0\r\n\
Accept: */*\r\n\
Accept-Encoding: gzip, deflate\r\n\
X-Appid: %s\r\n\
X-CurTime: %d\r\n\
X-Param: %s\r\n\
X-CheckSum: %s\r\n\
Content-Length: %d\r\n\r\n"
};

static const char base64char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int iBase64_Encode(const char *bindata, char *base64, int binlength)
{
    int i, j;
    unsigned char current;
    for ( i = 0, j = 0 ; i < binlength ; i += 3 ) 
    {   
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ; 
        if ( i + 1 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = base64char[(int)current];
    }
    base64[j] = '\0';
    return j;
}

const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// r specifies the per-round shift amounts
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
 
void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}
 
uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}
 
void MD5(const unsigned char *initial_msg, size_t initial_len, unsigned char *digest) {
 
    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;
 
    // Message (to prepare)
    uint8_t *msg = NULL;
 
    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;
 
    // Initialize variables - simple count in nibbles:
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
 
    //Pre-processing:
    //append "1" bit to message    
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append length mod (2^64) to message
 
    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
        ;
 
    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // append "0" bits
 
    // append the len in bits at the end of the buffer.
    to_bytes(initial_len*8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    to_bytes(initial_len>>29, msg + new_len + 4);
 
    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for(offset=0; offset<new_len; offset += (512/8)) {
 
        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i*4);
 
        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;
 
        // Main loop:
        for(i = 0; i<64; i++) {
 
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }
 
            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;
 
        }
 
        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
 
    }
 
    // cleanup
    free(msg);
 
    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}

static int Connect_TcpServer(const char *pszDomain, short nPort)
{
    int nRet;
    struct sockaddr_in server;
    struct hostent *pHost = gethostbyname(pszDomain);
    if(NULL == pHost || NULL == pHost->h_addr_list) {
		perror("gethostbyname");
		return -1;
	}
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0) {
		perror("socket");
		return -1;
	}
    /* 连接远程服务器 */
	server.sin_family = AF_INET;
	server.sin_port = htons(nPort);
	server.sin_addr = *(struct in_addr*)pHost->h_addr_list[0];
	nRet = connect(fd, (struct sockaddr *)&server, sizeof(server));
	if(-1 == nRet) {
		perror("connect");
		return -1;
	}
    return fd;
}

static unsigned int Get_NTP(const char *pszDomain, short nPort)
{
    int nRet, nSerLen;
    struct sockaddr_in server;
    struct hostent *pHost = gethostbyname(pszDomain);
    if(NULL == pHost || NULL == pHost->h_addr_list) {
		perror("gethostbyname");
		return 0;
	}
    
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		perror("socket");
		return 0;
	}
    /* 连接远程服务器 */
    nSerLen = sizeof(server);
    memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(nPort);
	server.sin_addr = *(struct in_addr*)pHost->h_addr_list[0];

    unsigned char pcRecvBuffer[48];
    static unsigned char packetBuffer[48] = {0xe3,0,6,0xec,0,0,0,0,0,0,0,0,0x31,0x4e,0x31,0x34};
    nRet = sendto(fd, packetBuffer, sizeof(packetBuffer), 0, (struct sockaddr *)&server, nSerLen);
    if(nRet < 0) {
        perror("sendto error:");
        return 0;
    }
    nRet = recvfrom(fd, pcRecvBuffer, sizeof(pcRecvBuffer), 0, (struct sockaddr *)&server, (socklen_t *)&nSerLen);
    if(nRet < 0) {
        perror("recvfrom error:");
        return 0;
    }

    unsigned int ulTime = 0;
    ulTime = (unsigned int)pcRecvBuffer[40];
    ulTime = pcRecvBuffer[40] << 24 | pcRecvBuffer[41] << 16 | pcRecvBuffer[42] << 8 | pcRecvBuffer[43];
    ulTime -= 2208988800;

    close(fd);
    return ulTime;
}

int AIUI_Audio2Text(const unsigned char* pcPcmBuffer, int nLen)
{
    int nRetry = 3;
    unsigned int ulTime;
    char pcBase64[1024] = {0};
    char pcCheckSum[1024] = {0};
    unsigned char pcMD5[16] = {0};
    unsigned char pcMD5_Dist[33] = {0};
    unsigned char pcHeadBuffer[4096];
    unsigned char pcRecvBuffer[4096] = {0};

    // NTP服务器
    // "time.windows.com",123
    // "0.cn.pool.ntp.org", 123
    // "1.cn.pool.ntp.org", 123
    // "2.cn.pool.ntp.org", 123
    // "3.cn.pool.ntp.org", 123
    // "cn.pool.ntp.org", 123

    while(nRetry--) {
        ulTime = Get_NTP("1.cn.pool.ntp.org", 123);
        if (ulTime > 0) break;
    }
    printf("current NTP time:%u\n", ulTime);
    printf("current Usr time:%u %2.2u:%2.2u:%2.2u\r\n", ulTime/31556736+1970, (ulTime/3600)%24+8, (ulTime/60)%60, ulTime%60);

    // 组装HTTP头信息
    iBase64_Encode(AIUI_PARAM, pcBase64, strlen(AIUI_PARAM));
    snprintf(pcCheckSum, sizeof(pcCheckSum), "%s%d%s", AIUI_API_KEY, ulTime, pcBase64);
    MD5((uint8_t *)pcCheckSum, strlen(pcCheckSum), pcMD5);
    for(int i=0; i<16; i++) {
        sprintf(pcMD5_Dist+i*2, "%2.2x",  pcMD5[i]);
    }
    snprintf((char *)pcHeadBuffer, sizeof(pcHeadBuffer), __audio2text, AIUI_APPID, ulTime, pcBase64, pcMD5_Dist, nLen);
    printf("\nrequeset header:\n%s\n", pcHeadBuffer);

    // 发送HTTP请求给服务端
    int fd = Connect_TcpServer("openapi.xfyun.cn", 80);
    if (-1 == fd) {
		perror("Connect_TcpServer error:");
		return -1;
	}
    write(fd, pcHeadBuffer, strlen(pcHeadBuffer));
    write(fd, pcPcmBuffer, nLen);
    read(fd, pcRecvBuffer, sizeof(pcRecvBuffer));
    close(fd);
    printf("\nrecv buffer:\n:%s\n", pcRecvBuffer);

    char pcText[4096];
    AIUI_GetResult(pcRecvBuffer, pcText, sizeof(pcText));
    printf("\nrecv text:\n:%s\n", pcText);

    return 0;
}

int AIUI_GetResult(const char* pcSrcBuffer, unsigned char* pcText, int nLen)
{
    char *pT = NULL;
    char *pS = NULL;
    char *pE = NULL;
    char *pN = (char *)pcSrcBuffer;
    if (strstr((char *)pcSrcBuffer, "HTTP/1.1 200 OK\r\n") != NULL)
    {
        while (strstr(pN, "\"result_id\":"))
        {
            pT = strstr(pN, "\"text\":");
            pS = strstr(pT, ":\"");
            pE = strstr(pS, "\",");
            if (pS != NULL && pE != NULL) {
                strncat(pcText, (char *)(pS+2), (pE-pS-2));
            }
            pN = pE+15;
        }
        return 0;
    }
    return -1;
}