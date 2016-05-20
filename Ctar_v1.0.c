/*tar의 소스 코드를 참고하여 tar의 기본 기능 구조 구현*/

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

#define BUF_SIZE 256

enum Mode {CREATE = 1, DELETE, RELEASE};

struct arch_header {
	char name[PATH_MAX];
	struct stat file_info;
	struct arch_header *next;
};

struct arch_data {
	char *buf;
};

struct arch_header *create_arch(struct arch_header *node, struct arch_header *temp, char *arch_name);
struct arch_header *delete_arch(char *entry, char *arch_name);
void release_arch(char *arch_name);
void print_list(struct arch_header *head);
void print_info(struct arch_header *head);
void insert(struct arch_header **phead, struct arch_header *newnode);

int main(int argc, char **argv)
{
	int option;
	char *path, *arch_name;
	int mod = -1, arch_name_taken = 0;
	int fd, len_read;
	struct arch_header *node = NULL;
	struct arch_header *temp = NULL;
	struct stat fstat;

	if(!arch_name_taken) //기본 묶기 파일 생성
	{
		arch_name = (char *)malloc(sizeof(char *) * strlen("custom(SHA1_X).tar") +1);
		strcpy(arch_name, "custom(SHA1_X).tar");
	}

	while ((option = getopt(argc, argv, "c:d:r:p:")) != -1) 
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
				temp->next = NULL;

				node = create_arch(node, temp, arch_name);

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

		case 'p':
			path = optarg;
			temp = (struct arch_header *)malloc(sizeof(struct arch_header));
			fd = open(path, O_RDONLY);
			while ((len_read = read(fd, temp, sizeof(struct arch_header))) > 0)
			{
				print_info(temp);
			}
			break;

		default:
			printf("option search error\n");
		}
	}

	print_list(node);//노드 출력

	return 0;
}

struct arch_header *create_arch(struct arch_header *node, struct arch_header *temp, char *arch_name)
{
	int arch_fd, len;
	struct stat fstat;
	void *buf;
	int len_read;
	int fd;
	struct arch_header *current = node;

	if(arch_fd == -1)
	{
		printf("create_arch error\n");
		return;
	}

	if(node == NULL)
	{
		node = temp;
	}
	else
	{
		while (current->next != NULL)
		{
			current = current->next;
		}
		current->next = temp;
	}

	fd = open(temp->name, O_RDONLY);

	arch_fd = open(arch_name, O_WRONLY | O_APPEND | O_CREAT, 0664);

	if(fd == -1)
	{
		printf("open error\n");

		return;
	}

	if(arch_fd == -1)
	{
		printf("arch_name open error\n");

		return;
	}

	//buf = malloc(BUF_SIZE);
	buf = malloc(temp->file_info.st_size);

	len = write(arch_fd, (struct arch_header *)temp, sizeof(struct arch_header));

	len = 0;

	while ((len_read = read(fd, buf, temp->file_info.st_size)) > 0)
	{
		len = write(arch_fd, buf, len_read);

		if(len_read != len)
		{
			printf("write error\n");
			free(buf);
			return;
		}
	}

	close(arch_fd);
	close(fd);

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

				insert(&node, temp);
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
	//print_list(node);

	return node;
}

void release_arch(char *arch_name)
{
	int arch_fd;
	int release_fd;
	int header_read, data_read, data_write;
	struct arch_header *head;

	arch_fd = open(arch_name, O_RDONLY, 0664);
	head = (struct arch_header *) malloc(sizeof(struct arch_header));

	while((header_read = read(arch_fd, head, sizeof(struct arch_header))) > 0)
	{
		release_fd = open(head->name, O_WRONLY | O_TRUNC | O_CREAT, 0664);
		printf("%s\n", head->name);
		data_read = read(arch_fd, head, head->file_info.st_size);
		data_write = write(release_fd, head, data_read);
		close(release_fd);
	}

	close(arch_fd);
}

void insert(struct arch_header **phead, struct arch_header *newnode)
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