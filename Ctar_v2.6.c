#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <utime.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>

//=============main===================

#define BUF_SIZE 4096
#define hashLen 8
enum Mode { CREATE = 1, DELETE, RELEASE };
enum FType { DIR_T = 1, FILE_T };

struct arch_header {
	char name[128];
	struct stat file_info;
	unsigned hash[hashLen];
	int locationIndex; //저장위치 알림
	int duplicateLocationIndex[150000]; //0번쨰는 중복데이터 여부 판단 : 0이면 중복 X, 1이상이면 중복데이터 개수
	int duplicateLocationIndexSize[150000];
	int unDuplicateLocationIndex[150000];
	int unDuplicateLocationIndexSize[150000];
	int chunkIndex[150000];
	int cut[150000]; //파일의 chunk를 자른 사이즈를 저장
	int chunks; // chunks의 갯수를 저장
	uint8_t *hv; //부분해쉬값 저장
	struct arch_header *next;
};

struct arch_data {
	char *buf;
};

uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

struct arch_header *create_arch(struct arch_header *node, struct arch_header *temp, char *arch_name);
struct arch_header *delete_arch(char *entry, char *arch_name);
void release_arch(char *arch_name);
void print_list(struct arch_header *head);
void print_info(struct arch_header *head);
void node_link(struct arch_header **phead, struct arch_header *newnode);

//===========main===================


//==========sha256==================
#define SWAP_BYTES

#define RL(x,n)   (((x) << n) | ((x) >> (32 - n)))
#define RR(x,n)   (((x) >> n) | ((x) << (32 - n)))

#define S0(x)  (RR((x), 2) ^ RR((x),13) ^ RR((x),22))
#define S1(x)  (RR((x), 6) ^ RR((x),11) ^ RR((x),25))
#define G0(x)  (RR((x), 7) ^ RR((x),18) ^ ((x) >> 3))
#define G1(x)  (RR((x),17) ^ RR((x),19) ^ ((x) >> 10))

#define BSWP(x,y)  _bswapw((uint32_t *)(x), (uint32_t)(y))
#define MEMCP(x,y,z) _memcp((x),(y),(z))

struct sha256_context {
	uint32_t buf[16];
	uint32_t hash[8];
	uint32_t len[2];
};

void sha256_init(struct sha256_context *sha);
void sha256_hash(struct sha256_context *sha, uint8_t *data, uint32_t len, uint32_t *K);
void sha256_done(struct sha256_context *sha, uint8_t *hash, uint32_t *K);

//==========sha256==================

//==========rabin===================
#define POLYNOMIAL 0x3DA3358B4DC173L
#define POLYNOMIAL_DEGREE 53
#define WINSIZE 64
#define AVERAGE_BITS 13
#define MINSIZE (4*1024)
#define MAXSIZE (16*1024)
#define MASK ((1<<AVERAGE_BITS)-1)
#define POL_SHIFT (POLYNOMIAL_DEGREE-8)

#ifndef __cdecl
#define __cdecl
#endif

struct rabin_t {
	uint8_t window[WINSIZE];
	unsigned int wpos;
	unsigned int count;
	unsigned int pos;
	unsigned int start;
	uint64_t digest;
};

struct chunk_t {
	unsigned int start;
	unsigned int length;
	uint64_t cut_fingerprint;
};

struct chunk_t last_chunk;
static int tables_initialized = 0;
static uint64_t mod_table[256];
static uint64_t out_table[256];

struct rabin_t *rabin_init(void);
void rabin_reset(struct rabin_t *h);
void rabin_slide(struct rabin_t *h, uint8_t b);
void rabin_append(struct rabin_t *h, uint8_t b);
int rabin_next_chunk(struct rabin_t *h, uint8_t *buf, unsigned int len);
struct chunk_t *rabin_finalize(struct rabin_t *h);

//==========rabin===================

int main(int argc, char **argv)
{
	int option;
	char *path, *arch_name;
	int mod = -1, arch_name_taken = 0;
	int fd, len_read;
	struct arch_header *node = NULL;
	struct arch_header *temp = NULL;
	struct stat fstat;
	int i, countIndex = 0;

	if (!arch_name_taken) //기본 묶기 파일 생성
	{
		arch_name = (char *)malloc(sizeof(char *) * strlen("custom_VLC.txt") + 1);
		strcpy(arch_name, "custom_VLC.txt");
	}

	while ((option = getopt(argc, argv, "c:d:r:h:")) != -1)
	{
		switch (option)
		{
		case 'c':
			path = optarg;
			mod = CREATE;
			if (mod == CREATE)
			{
				temp = (struct arch_header *)calloc(1, sizeof(struct arch_header));
				stat(path, &fstat);
				strcpy(temp->name, path);
				temp->file_info = fstat;
				temp->locationIndex = countIndex; //입력되는 위치값 지정
												  //temp->duplicateLocationIndex[0] = 0; //중복파일 위치값 지정
				temp->next = NULL;

				node = create_arch(node, temp, arch_name);

				countIndex++;
			}
			else
				printf("No creation\n");
			break;

		case 'd':
			path = optarg;
			mod = DELETE;
			if (mod == DELETE)
			{
				node = delete_arch(path, arch_name);
			}
			else
				printf("No deletion\n");
			break;

		case 'r':
			path = optarg;

			mod = RELEASE;
			if (mod == RELEASE)
			{
				release_arch(path);
			}
			else
				printf("No release\n");
			break;

		default:
			printf("option search error\n");
		}
	}

	print_list(node);
	printf("\n");

	return 0;
}

struct arch_header *create_arch(struct arch_header *node, struct arch_header *temp, char *arch_name)
{
	int arch_fd, fd, i, j, c, check = 0, match = 0, unmatch = 0, remaining, arrSize;
	int locationLen = 0;
	void *buf;
	struct arch_header *current = node; //연결을 위한 노드
	struct arch_header *hashnode = node; //검색을 위한 노드
	struct rabin_t *hash;
	struct sha256_context SHA256;
	uint8_t *ptr;
	unsigned int size = 0;
	size_t filesize;

	fd = open(temp->name, O_RDONLY);

	arch_fd = open(arch_name, O_WRONLY | O_CREAT | O_APPEND, 0664);

	hash = rabin_init();
	filesize = temp->file_info.st_size;
	arrSize = filesize / 4096;
	buf = (uint8_t *)malloc((filesize + 1) * sizeof(uint8_t));
	temp->hv = (uint8_t *)malloc(arrSize * 32 * sizeof(uint8_t));
	temp->chunks = 0;
	/*temp->cut = (int *)malloc(arrSize * sizeof(int));
	temp->chunkIndex = (int *)malloc(arrSize * sizeof(int));
	temp->duplicateLocationIndex = (int *)malloc(arrSize * sizeof(int));
	temp->duplicateLocationIndexSize = (int *)malloc(arrSize * sizeof(int));
	temp->unDuplicateLocationIndex = (int *)malloc(arrSize * sizeof(int));
	temp->unDuplicateLocationIndexSize = (int *)malloc(arrSize * sizeof(int));*/

	read(fd, buf, temp->file_info.st_size); //해시값을 추출을 위한 파일 읽기

	ptr = (uint8_t *)buf;

	while (1) //파일을 청크로 자르면서 해시값 추출
	{
		remaining = rabin_next_chunk(hash, ptr, filesize);

		if (remaining < 0)
		{
			break;
		}

		sha256_init(&SHA256);
		sha256_hash(&SHA256, ptr, (uint32_t)remaining, K);
		sha256_done(&SHA256, temp->hv + (temp->chunks * 32 * sizeof(uint8_t)), K);

		temp->chunks++;

		size += (unsigned int)remaining;
		temp->cut[temp->chunks] = size;
		temp->chunkIndex[temp->chunks] = temp->chunks;

		filesize -= remaining;
		ptr += remaining;

	}

	if (filesize > 0)
	{
		sha256_init(&SHA256);
		sha256_hash(&SHA256, ptr, (uint32_t)filesize, K);
		sha256_done(&SHA256, temp->hv + (temp->chunks * 32 * sizeof(uint8_t)), K);

		temp->chunks++;

		temp->cut[temp->chunks] = size + filesize;
		temp->chunkIndex[temp->chunks] = temp->chunks;
	}

	if (node == NULL) //첫번째 파일이 들어오면 실행하는 부분
	{
		node = temp;

		write(arch_fd, (struct arch_header *)temp, sizeof(struct arch_header));
		write(arch_fd, buf, temp->file_info.st_size);

		printf("1. %s : chunks : %d\n", temp->name, temp->chunks);
	}

	else if (hashnode->next == NULL) //두번째파일 해쉬 값 비교
	{
		for (i = 0; i < temp->chunks; i++)
		{
			for (j = 0; j < hashnode->chunks; j++)
			{
				match = 1;
				for (c = 0; c <= 32; c++)
				{
					if (temp->hv[j * 32 + c] != hashnode->hv[i * 32 + c])
					{
						match = 0;
						break;
					}
				}
				if (match == 1)//같은 내용이 검출
				{
					temp->duplicateLocationIndex[check] = hashnode->chunkIndex[i]; //청크의 위치 값
					temp->duplicateLocationIndexSize[check] = hashnode->cut[i + 1] - hashnode->cut[i]; //청크의 크기

					check++;
					break;
				}
			}

			if (match == 0) //유사성 검사를 통해 다른 내용만 검출해서 파일에 삽입
			{
				temp->unDuplicateLocationIndex[unmatch] = temp->chunkIndex[i]; //청크의 위치 값
				temp->unDuplicateLocationIndexSize[unmatch] = temp->cut[i + 1] - temp->cut[i]; //청크의 크기

				unmatch++;
			}
		}
		printf("2. %s : chunks : %d\n", temp->name, temp->chunks); //각 파일의 청크의 갯수 출력
		printf("2. check : %d\tunmatch : %d\tSimilarity : %f%%\n", check, unmatch, ((float)check / (float)temp->chunks) * 100);

		current->next = temp;

		write(arch_fd, (struct arch_header *)temp, sizeof(struct arch_header)); //두번째 파일의 헤더 삽입

		for (i = 0;i < temp->chunks;i++)
		{
			for (j = 0;j < unmatch;j++)
			{
				if (temp->chunkIndex[i] == temp->unDuplicateLocationIndex[j])
				{
					lseek(fd, locationLen, SEEK_SET);
					read(fd, buf, temp->cut[i + 1] - temp->cut[i]);
					write(arch_fd, buf, temp->cut[i + 1] - temp->cut[i]);
				}
				else
				{
					locationLen = locationLen + (temp->cut[i + 1] - temp->cut[i]);
				}
			}
		}

		unmatch = 0;
		check = 0;
		match = 0;
	}
	else
	{
		while (current->next != NULL) //세번째 파일이후 해쉬값 비교
		{
			while (hashnode->next != NULL) //해쉬값 검색
			{
				for (i = 0; i < temp->chunks; i++)
				{
					for (j = 0; j < hashnode->chunks; j++)
					{
						match = 1;
						for (c = 0; c <= 32; c++)
						{
							if (temp->hv[j * 32 + c] != hashnode->hv[i * 32 + c])
							{
								match = 0;
								break;
							}
						}
						if (match == 1)
						{
							temp->duplicateLocationIndex[check] = hashnode->chunkIndex[i]; //청크의 위치 값
							temp->duplicateLocationIndexSize[check] = hashnode->cut[i + 1] - hashnode->cut[i]; //청크의 크기

							check++;
							break;
						}
					}
					if (match == 0) //유사성 검사를 통해 다른 내용만 검출해서 파일에 삽입
					{
						temp->unDuplicateLocationIndex[unmatch] = temp->chunkIndex[i]; //청크의 위치 값
						temp->unDuplicateLocationIndexSize[unmatch] = temp->cut[i + 1] - temp->cut[i]; //청크의 크기

						unmatch++;
					}
				}
				printf("3_1. %s : chunks : %d\n", temp->name, temp->chunks); //각 파일의 청크의 갯수 출력
				printf("3_1. check : %d\tunmatch : %d\tSimilarity : %d\n", check, unmatch, (check / temp->chunks) * 100);

				hashnode = hashnode->next;

				unmatch = 0;
				check = 0;
				match = 0;
			}

			if (hashnode->next == NULL)
			{
				for (i = 0; i < temp->chunks; i++)
				{
					for (j = 0; j < hashnode->chunks; j++)
					{
						match = 1;
						for (c = 0; c <= 32; c++)
						{
							if (temp->hv[j * 32 + c] != hashnode->hv[i * 32 + c])
							{
								match = 0;
								break;
							}
						}
						if (match == 1)
						{
							temp->duplicateLocationIndex[check] = hashnode->chunkIndex[i]; //청크의 위치 값
							temp->duplicateLocationIndexSize[check] = hashnode->cut[i + 1] - hashnode->cut[i]; //청크의 크기

							check++;
							break;
						}
					}
					if (match == 0) //유사성 검사를 통해 다른 내용만 검출해서 파일에 삽입
					{
						temp->unDuplicateLocationIndex[unmatch] = temp->chunkIndex[i]; //청크의 위치 값
						temp->unDuplicateLocationIndexSize[unmatch] = temp->cut[i + 1] - temp->cut[i]; //청크의 크기

						unmatch++;
					}
				}
				printf("3_2. %s : chunks : %d\n", temp->name, temp->chunks); //각 파일의 청크의 갯수 출력
				printf("3_2. check : %d\tunmatch : %d\tSimilarity : %d\n", check, unmatch, (check/temp->chunks)*100);

				write(arch_fd, (struct arch_header *)temp, sizeof(struct arch_header)); //헤더 삽입

				for (i = 0;i < temp->chunks;i++)
				{
					for (j = 0;j < unmatch;j++)
					{
						if (temp->chunkIndex[i] == temp->unDuplicateLocationIndex[j])
						{
							lseek(fd, locationLen, SEEK_SET);
							read(fd, buf, temp->cut[i + 1] - temp->cut[i]);
							write(arch_fd, buf, temp->cut[i + 1] - temp->cut[i]);
						}
						else
						{
							locationLen = locationLen + (temp->cut[i + 1] - temp->cut[i]);
						}
					}
				}

				unmatch = 0;
				check = 0;
				match = 0;
			}

			current = current->next;
		}
	}

	close(arch_fd);
	close(fd);
	free(buf);

	return node;
}

struct arch_header *delete_arch(char *entry, char *arch_name)
{
	int arch_fd;
	int len, header_read, data_read[BUF_SIZE], check = 0;
	struct arch_header *head;
	struct arch_header *node = NULL;
	struct arch_header *temp = NULL;
	int count = 0, match = 0, unmatch = 0;
	struct arch_data data[BUF_SIZE];

	arch_fd = open(arch_name, O_RDONLY, 0664);

	head = (struct arch_header *) malloc(sizeof(struct arch_header));

	while ((header_read = read(arch_fd, head, sizeof(struct arch_header))) > 0)
	{
		if (strcmp(head->name, entry) != 0)
		{
			if (node->name == NULL)
			{
				node = (struct arch_header *) malloc(sizeof(struct arch_header));
				strcpy(node->name, head->name);
				node->file_info = head->file_info;
				node->next = NULL;

			}
			else
			{
				temp = (struct arch_header *) malloc(sizeof(struct arch_header));
				strcpy(temp->name, head->name);
				temp->file_info = head->file_info;
				temp->next = NULL;

				node_link(&node, temp);
			}

			check = lseek(arch_fd, head->file_info.st_size, SEEK_CUR);
			unmatch++;
		}
		else
		{
			check = lseek(arch_fd, head->file_info.st_size, SEEK_CUR);
			match++;
		}
		count++;
	}

	printf("read / count : %d, unmatch : %d, match : %d\n", count, unmatch, match);

	check = lseek(arch_fd, 0, SEEK_SET);
	count = unmatch;
	unmatch = 0;
	temp = node;

	while ((header_read = read(arch_fd, head, sizeof(struct arch_header))) > 0)
	{
		if (strcmp(head->name, temp->name) == 0 && unmatch <= count)
		{
			data[unmatch].buf = (char *)malloc(head->file_info.st_size);
			data_read[unmatch] = read(arch_fd, data[unmatch].buf, head->file_info.st_size);
			temp = temp->next;
			unmatch++;
		}
		else
		{
			check = lseek(arch_fd, head->file_info.st_size, SEEK_CUR);
		}
	}

	close(arch_fd);

	arch_fd = open(arch_name, O_WRONLY | O_TRUNC, 0664);
	temp = node;

	for (unmatch = 0; unmatch < count; unmatch++)
	{
		len = write(arch_fd, temp, sizeof(struct arch_header));
		len = write(arch_fd, data[unmatch].buf, data_read[unmatch]);
		temp = temp->next;
	}
	close(arch_fd);

	return node;
}

void release_arch(char *arch_name)
{
	int arch_fd;
	int release_fd;
	int header_read, data_read, data_write;
	int i, check = 0, sumlen = 0, remaining_chunks;
	struct arch_header *head, *prev;
	void *buf;

	int dupSum = 0, checkSum = 0;

	if ((arch_fd = open(arch_name, O_RDONLY)) == -1)
	{
		printf("Don't File open\n");
	}

	head = (struct arch_header *) malloc(sizeof(struct arch_header));
	prev = (struct arch_header *) malloc(sizeof(struct arch_header));

	printf("Total length %lu\n", lseek(arch_fd, 0, SEEK_END));
	lseek(arch_fd, 0, SEEK_SET);

	while ((header_read = read(arch_fd, head, sizeof(struct arch_header))) > 0) //현재 두번째에서 무한 반복중
	{
		printf("%s, %d, %d, %lu\n", head->name, head->chunks, header_read, lseek(arch_fd, 0, SEEK_CUR));
		int unDupLoc = lseek(arch_fd, 0, SEEK_CUR);

		if (head->duplicateLocationIndex[1] == 0) //중복이 없는 파일풀기
		{
			release_fd = open(head->name, O_WRONLY | O_TRUNC | O_CREAT, 0664);

			buf = (void *)malloc(head->file_info.st_size);

			data_read = read(arch_fd, buf, head->file_info.st_size);
			data_write = write(release_fd, buf, data_read);

			close(release_fd);
		}
		else if (head->duplicateLocationIndex[1] != 0)//중복이 있는 파일의 풀기, 복원하는 과정에서 몇번째 있는 파일의 중복 데이터를 복사할것지 판단이 필요
		{
			release_fd = open(head->name, O_WRONLY | O_TRUNC | O_CREAT, 0664);

			lseek(arch_fd, 0, SEEK_SET);

			int prev_read = read(arch_fd, prev, sizeof(struct arch_header));

			sumlen = header_read;

			for (i = 0; i < head->chunks; i++)
			{
				for (check = 0; check < prev->chunks; check++)
				{
					if (head->duplicateLocationIndex[i] == prev->chunkIndex[check] &&
						head->duplicateLocationIndexSize[i] == (prev->cut[check + 1] - prev->cut[check]))
					{
						lseek(arch_fd, sumlen, SEEK_SET); //이 부분을 주석을 하면 순차적인건 상관 없지만, 비 순차는 문제될까?

						data_read = read(arch_fd, buf, head->duplicateLocationIndexSize[i]);
						data_write = write(release_fd, buf, data_read);

						sumlen = sumlen + head->duplicateLocationIndexSize[i];
						remaining_chunks = i;
					}
				}
			}
			sumlen = unDupLoc;
			lseek(arch_fd, sumlen, SEEK_SET);

			for (i = 0; i < head->chunks - remaining_chunks; i++)
			{
				data_read = read(arch_fd, buf, head->unDuplicateLocationIndexSize[i]);
				data_write = write(release_fd, buf, data_read);

				sumlen = sumlen + head->unDuplicateLocationIndexSize[i];
			}
			//data_write = write(release_fd, "\0", 1); 
			//lseek(arch_fd, sumlen, SEEK_SET);
			sumlen = 0;
			close(release_fd);
		}

	}
	close(arch_fd);
}

void node_link(struct arch_header **phead, struct arch_header *newnode)
{
	struct arch_header *ptr = *phead;
	struct arch_header *p;

	if (*phead == NULL)	//연결리스트에 아무 내용이 없을때
	{
		(*phead) = newnode;
		newnode->next = NULL;
	}
	else
	{
		while (ptr != NULL)	//마지막 노드의 주소값을 찾는 반복문
		{
			p = ptr;
			ptr = ptr->next;
		}
		ptr = newnode;
		p->next = ptr;	//연결리스트의 끝에 newnode를 연결
	}
}

void print_list(struct arch_header *head)
{
	if (head == NULL)
	{
		printf("NULL\n");
	}
	else
	{
		printf("%s==>", head->name);
		print_list(head->next);
	}
}

void print_info(struct arch_header *head)
{
	if (head == NULL)
	{
		printf("End Data\n");
	}
	else
	{
		printf("FILE name : %s\n", head->name);
		/*printf("OWNER : %d\n", (int)head->file_info.st_uid);
		printf("GROUP : %d\n", (int)head->file_info.st_gid);
		printf("dev   : %d\n", (int)head->file_info.st_dev);
		printf("inode : %d\n", (int)head->file_info.st_ino);*/
		printf("FILE size is : %d\n", (int)head->file_info.st_size);
		/*printf("FILE blksize is : %d\n", (int)head->file_info.st_blksize);
		printf("FILE blocks is : %d\n", (int)head->file_info.st_blocks);
		printf("Last read time : %d\n", (int)head->file_info.st_atime);
		printf("Last modification time : %d\n", (int)head->file_info.st_mtime);
		printf("hard linked files : %d\n", (int)head->file_info.st_nlink);*/
		//printf("FILE cut : %u\n", head->cut);
		printf("FILE chunks : %d\n", head->chunks);
		puts("");
		print_info(head->next);
	}
}

//==========sha256==================

void _bswapw(uint32_t *p, uint32_t i)
{
	while (i--) p[i] = (RR(p[i], 24) & 0x00ff00ff) | (RR(p[i], 8) & 0xff00ff00);

}

void * __cdecl _memcp(void *d, const void *s, uint32_t sz)
{
	void *rv = d;

	while (sz--) *(char *)d = *(char *)s, d = (char *)d + 1, s = (char *)s + 1;

	return(rv);
}

void _rtrf(uint32_t *b, uint32_t *p, uint32_t i, uint32_t j, uint32_t *K)
{
#define B(x, y) b[(x-y) & 7]
#define P(x, y) p[(x+y) & 15]

	B(7, i) += (j ? (p[i & 15] += G1(P(i, 14)) + P(i, 9) + G0(P(i, 1))) : p[i & 15])
		+ K[i + j] + S1(B(4, i))
		+ (B(6, i) ^ (B(4, i) & (B(5, i) ^ B(6, i))));
	B(3, i) += B(7, i);
	B(7, i) += S0(B(0, i)) + ((B(0, i) & B(1, i)) | (B(2, i) & (B(0, i) ^ B(1, i))));

#undef P
#undef B
}

void _hash(struct sha256_context *ctx, uint32_t *K)
{
	uint32_t b[8], *p, j;

	b[0] = ctx->hash[0]; b[1] = ctx->hash[1]; b[2] = ctx->hash[2];
	b[3] = ctx->hash[3]; b[4] = ctx->hash[4]; b[5] = ctx->hash[5];
	b[6] = ctx->hash[6]; b[7] = ctx->hash[7];

	for (p = ctx->buf, j = 0; j < 64; j += 16)
		_rtrf(b, p, 0, j, K), _rtrf(b, p, 1, j, K), _rtrf(b, p, 2, j, K),
		_rtrf(b, p, 3, j, K), _rtrf(b, p, 4, j, K), _rtrf(b, p, 5, j, K),
		_rtrf(b, p, 6, j, K), _rtrf(b, p, 7, j, K), _rtrf(b, p, 8, j, K),
		_rtrf(b, p, 9, j, K), _rtrf(b, p, 10, j, K), _rtrf(b, p, 11, j, K),
		_rtrf(b, p, 12, j, K), _rtrf(b, p, 13, j, K), _rtrf(b, p, 14, j, K),
		_rtrf(b, p, 15, j, K);

	ctx->hash[0] += b[0]; ctx->hash[1] += b[1]; ctx->hash[2] += b[2];
	ctx->hash[3] += b[3]; ctx->hash[4] += b[4]; ctx->hash[5] += b[5];
	ctx->hash[6] += b[6]; ctx->hash[7] += b[7];

} /* _hash */

void sha256_init(struct sha256_context *ctx)
{
	ctx->len[0] = ctx->len[1] = 0;
	ctx->hash[0] = 0x6a09e667; ctx->hash[1] = 0xbb67ae85;
	ctx->hash[2] = 0x3c6ef372; ctx->hash[3] = 0xa54ff53a;
	ctx->hash[4] = 0x510e527f; ctx->hash[5] = 0x9b05688c;
	ctx->hash[6] = 0x1f83d9ab; ctx->hash[7] = 0x5be0cd19;

} /* sha256_init */

void sha256_hash(struct sha256_context *ctx, uint8_t *dat, uint32_t sz, uint32_t *K)
{
	register uint32_t i = ctx->len[0] & 63, l, j;

	if ((ctx->len[0] += sz) < sz)  ++(ctx->len[1]);

	for (j = 0, l = 64 - i; sz >= l; j += l, sz -= l, l = 64, i = 0)
	{
		MEMCP(&ctx->buf[i], &dat[j], l);
		BSWP(ctx->buf, 16);
		_hash(ctx, K);
	}
	MEMCP(&ctx->buf[i], &dat[j], sz);

} /* _hash */

void sha256_done(struct sha256_context *ctx, uint8_t *buf, uint32_t *K)
{
	uint32_t i = (uint32_t)(ctx->len[0] & 63), j = ((~i) & 3) << 3;

	BSWP(ctx->buf, (i + 3) >> 2);

	ctx->buf[i >> 2] &= 0xffffff80 << j;  /* add padding */
	ctx->buf[i >> 2] |= 0x00000080 << j;

	if (i < 56) i = (i >> 2) + 1;
	else ctx->buf[15] ^= (i < 60) ? ctx->buf[15] : 0, _hash(ctx, K), i = 0;

	while (i < 14) ctx->buf[i++] = 0;

	ctx->buf[14] = (ctx->len[1] << 3) | (ctx->len[0] >> 29); /* add length */
	ctx->buf[15] = ctx->len[0] << 3;

	_hash(ctx, K);

	for (i = 0; i < 32; i++)
		ctx->buf[i % 16] = 0, /* may remove this line in case of a DIY cleanup */
		buf[i] = (uint8_t)(ctx->hash[i >> 2] >> ((~i & 3) << 3));

}

//==========sha256==================

//==========rabin===================

static int deg(uint64_t p) {
	uint64_t mask = 0x8000000000000000L;
	int i;

	for (i = 0; i < 64; i++)
	{
		if ((mask & p) > 0) {
			return 63 - i;
		}

		mask >>= 1;
	}

	return -1;
}

static uint64_t mod(uint64_t x, uint64_t p)
{// Mod calculates the remainder of x divided by p.
	while (deg(x) >= deg(p)) {
		unsigned int shift = deg(x) - deg(p);

		x = x ^ (p << shift);
	}

	return x;
}

static uint64_t append_byte(uint64_t hash, uint8_t b, uint64_t pol) {
	hash <<= 8;
	hash |= (uint64_t)b;

	return mod(hash, pol);
}

static void calc_tables(void) {
	// calculate table for sliding out bytes. The byte to slide out is used as
	// the index for the table, the value contains the following:
	// out_table[b] = Hash(b || 0 ||        ...        || 0)
	//                          \ windowsize-1 zero bytes /
	// To slide out byte b_0 for window size w with known hash
	// H := H(b_0 || ... || b_w), it is sufficient to add out_table[b_0]:
	//    H(b_0 || ... || b_w) + H(b_0 || 0 || ... || 0)
	//  = H(b_0 + b_0 || b_1 + 0 || ... || b_w + 0)
	//  = H(    0     || b_1 || ...     || b_w)
	//
	// Afterwards a new byte can be shifted in.
	int b, i, k, c;

	for (b = 0; b < 256; b++) {
		uint64_t hash = 0;

		hash = append_byte(hash, (uint8_t)b, POLYNOMIAL);
		for (i = 0; i < WINSIZE - 1; i++) {
			hash = append_byte(hash, 0, POLYNOMIAL);
		}
		out_table[b] = hash;
	}
	// calculate table for reduction mod Polynomial
	k = deg(POLYNOMIAL);
	for (b = 0; b < 256; b++) {
		// mod_table[b] = A | B, where A = (b(x) * x^k mod pol) and  B = b(x) * x^k
		//
		// The 8 bits above deg(Polynomial) determine what happens next and so
		// these bits are used as a lookup to this table. The value is split in
		// two parts: Part A contains the result of the modulus operation, part
		// B is used to cancel out the 8 top bits so that one XOR operation is
		// enough to reduce modulo Polynomial
		mod_table[b] = mod(((uint64_t)b) << k, POLYNOMIAL) | ((uint64_t)b) << k;
	}
}

int getAbit(uint64_t x, int n) { // getbit()
	uint64_t y = ((x >> n) & 1);
	return (int)y;
}

void rabin_append(struct rabin_t *h, uint8_t b) {
	uint8_t index = (uint8_t)(h->digest >> POL_SHIFT);//POL_SHIFT 45
	h->digest <<= 8;
	h->digest |= (uint64_t)b;
	h->digest ^= mod_table[index];
}

void rabin_slide(struct rabin_t *h, uint8_t b) {
	uint8_t out = h->window[h->wpos];
	h->window[h->wpos] = b;
	h->digest = (h->digest ^ out_table[out]);
	h->wpos = (h->wpos + 1) % WINSIZE;

	rabin_append(h, b);
}

void rabin_reset(struct rabin_t *h) {
	int i;
	for (i = 0; i < WINSIZE; i++)
		h->window[i] = 0;
	h->digest = 0;
	h->wpos = 0;
	h->count = 0;
	h->digest = 0;

	rabin_slide(h, 1);
}

int rabin_next_chunk(struct rabin_t *h, uint8_t *buf, unsigned int len) {
	unsigned int i, pos;
	FILE *fw;
	int c;

	for (i = 0; i < len; i++) {
		uint8_t b = *buf++;

		rabin_slide(h, b);

		h->count++;
		h->pos++;

		if ((h->count >= MINSIZE && ((h->digest & MASK) == 0)) || h->count >= MAXSIZE) {
			last_chunk.start = h->start;
			last_chunk.length = h->count;
			last_chunk.cut_fingerprint = h->digest;

			// keep position
			pos = h->pos;
			rabin_reset(h);
			h->start = pos;
			h->pos = pos;
			return i + 1;
		}
	}
	return -1;
}

struct rabin_t *rabin_init(void) {

	struct rabin_t *h;
	if (!tables_initialized) {
		calc_tables();
		tables_initialized = 1;
	}

	if ((h = (struct rabin_t *)malloc(sizeof(struct rabin_t))) == NULL) {

	}

	rabin_reset(h);

	return h;
}

struct chunk_t *rabin_finalize(struct rabin_t *h) {
	if (h->count == 0) {
		last_chunk.start = 0;
		last_chunk.length = 0;
		last_chunk.cut_fingerprint = 0;
		return NULL;
	}

	last_chunk.start = h->start;
	last_chunk.length = h->count;
	last_chunk.cut_fingerprint = h->digest;
	return &last_chunk;
}

//==========rabin===================