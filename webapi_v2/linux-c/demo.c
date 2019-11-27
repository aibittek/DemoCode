#include "tinycap.h"
#include "asr.h"

static int Read_File(const char *pszPathname, unsigned char **ppBuffer, int *pnLen)
{
    int nRet = -1, nReadRet;
    struct stat stStat;

    if (NULL == pszPathname || NULL == ppBuffer || NULL == pnLen) return -1;

    int fdr = open(pszPathname, O_RDONLY);
	if (0 > fdr) {
		perror("open:");
		return -1;
	}

    do {
        if (0 > fstat(fdr, &stStat)) {
            perror("fstat:");
            break;
        }
        *ppBuffer = (unsigned char *)malloc(stStat.st_size);
        if (NULL == *ppBuffer) {
            perror("malloc:");
            break;
        }
        nReadRet = read(fdr, *ppBuffer, stStat.st_size);
        *pnLen = nReadRet;
        if (nReadRet != stStat.st_size) {
            perror("read:");
            break;
        }
        nRet = 0;
    } while(0);

    if (fdr > 0) close(fdr);
    if (nRet && *ppBuffer) {
        free(*ppBuffer);
        *ppBuffer = NULL;
    }

    // int fdw = open("write.pcm", O_CREAT | O_TRUNC | O_WRONLY, 0666);
    // write(fdw, *ppBuffer, *pnLen);
    // close(fdw);

    return nRet;
}

int main(int argc, char *argv[])
{
    int nLen;
    unsigned char *pcRecvBuffer = NULL;

    tinycap(argc, argv);

    int nError = Read_File(argv[1], &pcRecvBuffer, &nLen);
    if (!nError) AIUI_Audio2Text(pcRecvBuffer, nLen);

    if (pcRecvBuffer) free(pcRecvBuffer);
    return 0;
}