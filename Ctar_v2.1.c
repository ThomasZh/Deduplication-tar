/* SHA-1 whole file chunking / FLC */

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

#define BUF_SIZE 4096
#define SHA1CircularShift(bits,word)  ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))
enum Mode {CREATE = 1, DELETE, RELEASE};
enum FType {DIR_T = 1, FILE_T};

struct arch_header {
	char name[PATH_MAX];
	struct stat file_info;
	unsigned hash[5];
	int locationIndex; //저장위치 알림
	int duplicateLocationIndex[255]; //0번쨰는 중복데이터 여부 판단 : 0이면 중복 X, 1이상이면 중복데이터 개수
	struct arch_header *next;
};

struct arch_data {
	char *buf;
};

typedef struct SHA1Context
{
	unsigned Message_Digest[5]; 

	unsigned Length_Low;  
	unsigned Length_High; 

	unsigned char Message_Block[64]; 
	int Message_Block_Index;  

	int Computed; 
	int Corrupted; 

} SHA1Context;

struct arch_header *create_arch(struct arch_header *node, struct arch_header *temp, char *arch_name);
struct arch_header *delete_arch(char *entry, char *arch_name);
void release_arch(char *arch_name);
void print_list(struct arch_header *head);
void print_info(struct arch_header *head);
void node_link(struct arch_header **phead, struct arch_header *newnode);
void SHA1Reset(SHA1Context *);
int SHA1Result(SHA1Context *);
void SHA1Input( SHA1Context *, const unsigned char *, unsigned);
void SHA1ProcessMessageBlock(SHA1Context *);
void SHA1PadMessage(SHA1Context *);

int main(int argc, char **argv)
{
	int option;
	char *path, *arch_name;
	int mod = -1, arch_name_taken = 0;
	int fd, len_read;
	struct arch_header *node = NULL;
	struct arch_header *temp = NULL;
	struct stat fstat;
	SHA1Context sha;
	int i, countIndex = 1;

	if(!arch_name_taken) //기본 묶기 파일 생성
	{
		arch_name = (char *)malloc(sizeof(char *) * strlen("custom(SHA1_O).txt") +1);
		strcpy(arch_name, "custom(SHA1_O).txt");
	}

	while ((option = getopt(argc, argv, "c:d:r:h:")) != -1) 
	{
		switch (option) 
		{
		case 'c':
			path = optarg;
			mod = CREATE;
			if(mod == CREATE)
			{
				temp = (struct arch_header *)calloc(1, sizeof(struct arch_header));
				stat(path, &fstat);
				strcpy(temp->name, path);
				temp->file_info = fstat;
				temp->locationIndex = countIndex; //입력되는 위치값 지정
				temp->duplicateLocationIndex[0] = 0; //중복파일 위치값 지정
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
			if(mod == DELETE)
			{
				node = delete_arch(path, arch_name);
			}
			else
				printf("No deletion\n");
			break;

		case 'r':
			path = optarg;
			mod = RELEASE;
			if(mod == RELEASE)
			{
				release_arch(arch_name);
			}
			else
				printf("No release\n");
			break;

		case 'h':
			path = optarg;
			SHA1Reset(&sha);
			SHA1Input(&sha, (const unsigned char *) path, strlen(path));

			if (!SHA1Result(&sha))
			{
				fprintf(stderr, "ERROR-- could not compute message digest\n");
			}
			else
			{
				printf("%s\n", path);
				for(i = 0; i < 5 ; i++)
				{
					printf("%x ", sha.Message_Digest[i]);
				}
			}

			break;

		default:
			printf("option search error\n");
		}
	}

	print_list(node);

	return 0;
}

struct arch_header *create_arch(struct arch_header *node, struct arch_header *temp, char *arch_name)
{
	int arch_fd, len;
	struct stat fstat;
	void *buf;
	int len_read;
	int fd;
	struct arch_header *current = node; //연결을 위한 노드
	struct arch_header *hashnode = node; //검색을 위한 노드
	SHA1Context sha;
	int i, match = 0;
	unsigned hash[5];

	fd = open(temp->name, O_RDONLY);

	arch_fd = open(arch_name, O_WRONLY | O_CREAT | O_APPEND, 0664);

	//buf = malloc(BUF_SIZE);
	buf = malloc(temp->file_info.st_size);

	while ((len_read = read(fd, buf, temp->file_info.st_size)) > 0)
	{
		SHA1Reset(&sha);
		SHA1Input(&sha, (const unsigned char *) buf, strlen((const unsigned char *) buf));

		if (!SHA1Result(&sha))
		{
			fprintf(stderr, "ERROR-- could not compute message digest\n");
		}
		else
		{
			for(i = 0; i < 5 ; i++) //각 파일의 해쉬값 추출
			{
				printf("%X ", sha.Message_Digest[i]);
				temp->hash[i] = sha.Message_Digest[i];
			}
			printf("\n");
		}

		if(node == NULL) //첫번째 파일이 들어오면 실행하는 부분
		{
			node = temp;
			len = write(arch_fd, (struct arch_header *)temp, sizeof(struct arch_header));
			len = write(arch_fd, buf, len_read);
		}
		else
		{
			if(hashnode->next == NULL) //두번째파일 해쉬 값 비교
			{
				for(i = 0; i < 5 ; i++)
				{
					if(hashnode->hash[i] == temp->hash[i])
					{
						match++;
						temp->duplicateLocationIndex[1] = hashnode->locationIndex;
					}
				}

				if(match == 5 && (match%5 == 0))
				{
					temp->duplicateLocationIndex[0] = 1;
					
					len = write(arch_fd, (struct arch_header *)temp, sizeof(struct arch_header));
					match = 0;					
				}
				else
				{
					len = write(arch_fd, (struct arch_header *)temp, sizeof(struct arch_header));
					len = write(arch_fd, buf, len_read);
					match = 0;
				}

				current->next = temp;
			}
			else
			{
				while (current->next != NULL) //세번째 파일이후 해쉬값 비교
				{
					while(hashnode->next != NULL) //해쉬값 검색
					{
						for(i = 0; i < 5 ; i++)
						{
							if(hashnode->hash[i] == temp->hash[i])
							{
								match++;
								temp->duplicateLocationIndex[1] = hashnode->locationIndex;
							}
						}
						hashnode = hashnode->next;
					}
					if(hashnode->next == NULL)
					{
						for(i = 0; i < 5 ; i++)
						{
							if(hashnode->hash[i] == temp->hash[i])
							{
								match++;
								temp->duplicateLocationIndex[1] = hashnode->locationIndex;
							}
						}
					}
					current = current->next;
				}
				if(match >= 5 && match%5 == 0)
				{
					temp->duplicateLocationIndex[0] = 1;
					
					current->next = temp;
					len = write(arch_fd, (struct arch_header *)temp, sizeof(struct arch_header));
					match = 0;
				}
				else
				{
					current->next = temp;
					len = write(arch_fd, (struct arch_header *)temp, sizeof(struct arch_header));
					len = write(arch_fd, buf, len_read);
					match = 0;
				}
			}
		}
	}

	close(arch_fd);
	close(fd);
	free(buf);

	printf("%s, DLI0 : %d, DLI1 : %d\n\n", temp->name, temp->duplicateLocationIndex[0], temp->duplicateLocationIndex[1]); 

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

	while((header_read = read(arch_fd, head, sizeof(struct arch_header))) > 0)
	{		
		if(strcmp(head->name, entry) != 0)
		{
			if(node->name == NULL)
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

	while((header_read = read(arch_fd, head, sizeof(struct arch_header))) > 0)
	{		
		if(strcmp(head->name, temp->name) == 0 && unmatch<=count)
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

	for(unmatch = 0; unmatch < count; unmatch++)
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
	int i;
	struct arch_header *head;

	arch_fd = open(arch_name, O_RDONLY, 0664);
	head = (struct arch_header *) malloc(sizeof(struct arch_header));

	while((header_read = read(arch_fd, head, sizeof(struct arch_header))) > 0)
	{
		/*release_fd = open(head->name, O_WRONLY | O_TRUNC | O_CREAT, 0664); 
		printf("%s\n", head->name);
		data_read = read(arch_fd, head, head->file_info.st_size);
		data_write = write(release_fd, head, data_read);
		close(release_fd);*/

		release_fd = open(head->name, O_WRONLY | O_TRUNC | O_CREAT, 0664); 
		printf("%s\n", head->name);

		for(i = 0; i < 5 ; i++) //각 파일의 해쉬값 추출
		{
			printf("%X ", head->hash[i]);
		}
		printf("\n");

		//data_read = read(arch_fd, head, head->file_info.st_size);
		//data_write = write(release_fd, head, data_read);
		close(release_fd);
	}

	close(arch_fd);
}

void node_link(struct arch_header **phead, struct arch_header *newnode)
{
	struct arch_header *ptr = *phead;
	struct arch_header *p;

	if(*phead==NULL)	//연결리스트에 아무 내용이 없을때
	{
		(*phead)=newnode;           
		newnode->next=NULL;
	}
	else
	{
		while(ptr!=NULL)	//마지막 노드의 주소값을 찾는 반복문
		{
			p=ptr;
			ptr=ptr->next;
		} 
		ptr=newnode;	
		p->next=ptr;	//연결리스트의 끝에 newnode를 연결
	}
}

void print_list(struct arch_header *head)
{
	if( head == NULL ) 
	{
		printf("NULL\n");
	}
	else
	{
		printf("%s==>",head->name);
		print_list(head->next);
	}  
}

void print_info(struct arch_header *head)
{
	if(head == NULL)
	{
		printf("End Data\n");
	}
	else
	{
		printf("FILE name : %s\n", head->name);
		printf("OWNER : %d\n", (int)head->file_info.st_uid);
		printf("GROUP : %d\n", (int)head->file_info.st_gid);
		printf("dev   : %d\n", (int)head->file_info.st_dev);
		printf("inode : %d\n", (int)head->file_info.st_ino);
		printf("FILE size is : %d\n", (int)head->file_info.st_size);
		printf("FILE blksize is : %d\n", (int)head->file_info.st_blksize);
		printf("FILE blocks is : %d\n", (int)head->file_info.st_blocks);
		printf("Last read time : %d\n", (int)head->file_info.st_atime);
		printf("Last modification time : %d\n", (int)head->file_info.st_mtime);
		printf("hard linked files : %d\n", (int)head->file_info.st_nlink);
		puts("");
		print_info(head->next);
	}
}

void SHA1Reset(SHA1Context *context)
{
	context->Length_Low             = 0;
	context->Length_High            = 0;
	context->Message_Block_Index    = 0;

	context->Message_Digest[0]      = 0x67452301;
	context->Message_Digest[1]      = 0xEFCDAB89;
	context->Message_Digest[2]      = 0x98BADCFE;
	context->Message_Digest[3]      = 0x10325476;
	context->Message_Digest[4]      = 0xC3D2E1F0;

	context->Computed   = 0;
	context->Corrupted  = 0;
}

int SHA1Result(SHA1Context *context)
{
	if (context->Corrupted)
	{
		return 0;
	}

	if (!context->Computed)
	{
		SHA1PadMessage(context);
		context->Computed = 1;
	}

	return 1;
}

void SHA1Input(SHA1Context *context, const unsigned char *message_array, unsigned length)
{
	if (!length)
	{
		return;
	}

	if (context->Computed || context->Corrupted)
	{
		context->Corrupted = 1;
		return;
	}

	while(length-- && !context->Corrupted)
	{
		context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);

		context->Length_Low += 8;
		/* Force it to 32 bits */
		context->Length_Low &= 0xFFFFFFFF;
		if (context->Length_Low == 0)
		{
			context->Length_High++;
			/* Force it to 32 bits */
			context->Length_High &= 0xFFFFFFFF;
			if (context->Length_High == 0)
			{
				/* Message is too long */
				context->Corrupted = 1;
			}
		}

		if (context->Message_Block_Index == 64)
		{
			SHA1ProcessMessageBlock(context);
		}

		message_array++;
	}
}

void SHA1ProcessMessageBlock(SHA1Context *context)
{
	const unsigned K[] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
	int         t;               
	unsigned    temp;            
	unsigned    W[80];           
	unsigned    A, B, C, D, E;   

	for(t = 0; t < 16; t++)
	{
		W[t] = ((unsigned) context->Message_Block[t * 4]) << 24;
		W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;
		W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;
		W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);
	}

	for(t = 16; t < 80; t++)
	{
		W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
	}

	A = context->Message_Digest[0];
	B = context->Message_Digest[1];
	C = context->Message_Digest[2];
	D = context->Message_Digest[3];
	E = context->Message_Digest[4];

	for(t = 0; t < 20; t++)
	{
		temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	for(t = 20; t < 40; t++)
	{
		temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	for(t = 40; t < 60; t++)
	{
		temp = SHA1CircularShift(5,A) +
			((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	for(t = 60; t < 80; t++)
	{
		temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	context->Message_Digest[0] = (context->Message_Digest[0] + A) & 0xFFFFFFFF;
	context->Message_Digest[1] = (context->Message_Digest[1] + B) & 0xFFFFFFFF;
	context->Message_Digest[2] = (context->Message_Digest[2] + C) & 0xFFFFFFFF;
	context->Message_Digest[3] = (context->Message_Digest[3] + D) & 0xFFFFFFFF;
	context->Message_Digest[4] = (context->Message_Digest[4] + E) & 0xFFFFFFFF;

	context->Message_Block_Index = 0;
}

void SHA1PadMessage(SHA1Context *context)
{
	if (context->Message_Block_Index > 55)
	{
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while(context->Message_Block_Index < 64)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}

		SHA1ProcessMessageBlock(context);

		while(context->Message_Block_Index < 56)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}
	else
	{
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while(context->Message_Block_Index < 56)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}

	context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
	context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
	context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
	context->Message_Block[59] = (context->Length_High) & 0xFF;
	context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
	context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
	context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
	context->Message_Block[63] = (context->Length_Low) & 0xFF;

	SHA1ProcessMessageBlock(context);
}

