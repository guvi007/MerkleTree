#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

static int filesys_inited = 0;
struct filesys fs[1024];
int numFs = 0;
/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
	char *tmp = (char*)sha1;
	int l = strlen(tmp);
	for(int i=0;i<l;++i) {
		int a = *tmp;
		if(a >= 0 && a <= 31) {
			*tmp = (char)(a+32);
			// printf("%s\n", "Replaced slash n");
		}
		tmp++;
	}
	for(int i=l;i<20;++i) {
		*tmp = '|';
		tmp++;
	}
	// printf("lebiwfhyiefhilehfilefh = %ld\n", strlen((char*)sha1));

}

void build(char *segmentTree[], char* blockHash[], int start, int end, int index)
{
	segmentTree[index] = malloc(21*sizeof(char));
	memset(segmentTree[index],'\0',21); //mark

	if(start>end){
		return;
	}
	else if(start == end) {
		strcpy(segmentTree[index], blockHash[start]);
	}
	else {
		int mid = (start + end)/2;

		build(segmentTree, blockHash, start, mid, 2*index + 1);
		build(segmentTree, blockHash, mid+1, end, 2*index + 2);

		char *sha1 = malloc(41*sizeof(char));
		memset(sha1,'\0',41); //mark
		strcpy(sha1, segmentTree[2*index + 1]);
		char *sha2 = malloc(21*sizeof(char));
		memset(sha2,'\0',21); //mark
		strcpy(sha2, segmentTree[2*index + 2]);

		strcat(sha1,sha2);
		char* shacat = malloc(21*sizeof(char));
		memset(shacat,'\0',21); //mark
		get_sha1_hash (sha1, strlen(sha1), (void*)shacat);
		strcpy(segmentTree[index], shacat);
	}
}

void createSegment( char* blockHash[], int numBlocks, char fileHash[] )
{
	if(numBlocks==0)
	{
		// printf("creatSegment : returning empty string\n");
		char empty[] = "00000000000000000000";
		empty[20] = '\0';
		strcpy(fileHash,empty);
		return;
	}
	// printf("createSegment : entered\n");

	int flag = 0;
	if(numBlocks & 1) {
			numBlocks -= 1;
			flag = 1;
	}
	char* segmentTree[4 * numBlocks];
	build(segmentTree, blockHash, 0, numBlocks-1, 0);

	if(flag == 1) {
		char *shacat = malloc(41*sizeof(char));
		memset(shacat,'\0',41); //mark

		if(numBlocks!=0)
			strcpy(shacat,segmentTree[0]);
		strcat(shacat,blockHash[numBlocks]);

		get_sha1_hash(shacat,strlen(shacat),fileHash);
		// printf("shacat ---- %s\n", shacat);
		// printf("shacat filhash = %s\n",fileHash );
		// printf("lebngtj = %ld\n", strlen(fileHash));
	}
	else
		strcpy(fileHash,segmentTree[0]);

	// printf("sha merkel tree = %s\n", fileHash);
}

void buildMerkle(const char* pathname, char fileHash[])
{
	// printf("buildMerkle : entered\n");
	int fd = open(pathname,O_RDONLY,0);
	if(fd==-1)
	{
		//printf("ERROR buildMerkle : fd = -1\n");
		exit(0);
	}
	int filesize=lseek(fd,0,SEEK_END);
	lseek(fd,0,SEEK_SET);
	// printf("\nbuildMerkle , filesize: %d\n",filesize);

	int blocks = (filesize + 63) / 64;
	// printf("num Blocks = %d\n", blocks);
	char buf[65];
	char **blockHash = malloc(blocks * sizeof(char*));
	for(int i=0; i<blocks; i++)
	{
		memset(buf,'\0',65);
		read(fd,buf,64);
		char sha1[21];
		memset(sha1,'\0',21);
		get_sha1_hash(buf,strlen(buf),sha1);
		blockHash[i] = malloc(21*sizeof(char));
		strcpy(blockHash[i],sha1);
		// printf("block data = %s\n", blockHash[i]);
	}

	createSegment(blockHash, blocks,fileHash);
	close(fd);
}

int get_entry(const char* fname, char sha2[])
{
	// printf("get_entry : Entering\n");
	FILE *fp = fopen("secure.txt", "r" );
	// printf("getEntry Filename = %s\n", fname);
	char line[256];
	memset(line,'\0',256);

	while (fgets(line,sizeof line,fp) != NULL)
	{
		if( line != NULL || line[0] !='\n' )
		{
			char* rest = NULL;
			char* filename = strtok_r(line, " ",&rest);
			// printf("getEntry Filename 1 = %s\n", filename);
			if(strcmp(filename, fname) == 0) {
				// printf("%s\n", "yoyoyoyoyoy");
				for(int i=0; i<20;++i) {
					sha2[i] = *rest;
					rest++;
				}
				fclose(fp);
				return 1;
			}

			memset(line,'\0',256);
		}
		else
		{
			//printf(" Found an empty Line which I should NOt have \n");
		}
	}
	fclose(fp);
	return 0;
}

void add_entry(const char* fname, char sha1[], int alloc)
{
	// printf("add_entry : Entering\n");
	FILE *fp = fopen("secure.txt", "a" );
	char buff[256];
	memset(buff,'\0',sizeof(buff));
	strcpy(buff, fname);
	strcat(buff, " ");
	strcat(buff, sha1);
	strcat(buff, "\n");
	// printf("BUFFER ADD ENTRY = %s\n", buff);
	fputs(buff,fp);
	// fflush(fp);
	if(alloc != 0) {
		strcpy(fs[numFs].filename,fname);
		strcpy(fs[numFs].sha,sha1);
		// fs[numFs].fd = fd;
		// printf("structure ============ %s %s %d\n", fs[numFs].filename, fs[numFs].sha, fs[numFs].fd);
		numFs++;
	}
	fclose(fp);
	// printf("add_entry : exiting\n");
}

void  update_entry(const char* fname,char newsha1[]) {
	char line[256],line2[256];
	memset(line,'\0',256);
	memset(line2,'\0',256);
	FILE *fp1 = fopen("secure.txt","r");
	FILE *tempfp = fopen("tempsecure.txt","w");
	while (fgets(line,sizeof line,fp1) != NULL)
	{
		if( line != NULL || line[0] !='\n' )
		{
			strcpy(line2, line);
			char* rest = NULL;
			char* filename = strtok_r(line, " ",&rest);
			if(strcmp(filename,fname) != 0)
			{
				fputs(line2,tempfp);
				// fflush(tempfp);
			}
			memset(line,'\0',256);
			memset(line2,'\0',256);
		}
		else
		{
			//printf(" Found an empty Line which I should NOt have \n");
		}
	}

	fclose(tempfp);
	fclose(fp1);
	remove("secure.txt");
	if(rename("tempsecure.txt","secure.txt") == 0){
		 // printf("Renamed tempsecure Successfully\n");
	}
	add_entry(fname,newsha1,0);
}



int checkIntegrity(char secureEntry[], char filehash[])
{
	if(strcmp(secureEntry,filehash)==0)
		return 0;
	//printf("checkIntegrity : secureEntry(len:%ld) : %s, fileHash(len:%ld) : %s\n", strlen(secureEntry),secureEntry, strlen(filehash),filehash);
	return -1;
}

/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */
int s_open (const char *pathname, int flags, mode_t mode)
{
	// printf("s_open entered = %s\n", pathname);
	assert (filesys_inited);

	int fd = open (pathname, flags, mode);
	if(fd==-1){
		//printf("s_open : fd = -1\n");
		return fd;
	}

	// int truncated = (flags & O_TRUNC);

	char sha1[21], sha2[21];
	memset(sha1,'\0',21);
	memset(sha2,'\0',21);
	buildMerkle(pathname, sha1);

	if(get_entry(pathname, sha2) == 1) {
		// printf("sha from getEntry = %s\n", sha2);
		if(checkIntegrity(sha2, sha1) == -1){
			s_close(fd);
			return -1;
		}
	}
	else {
		// printf("couldn't find entry, adding entry\n");
		add_entry(pathname, sha1, 1);
	}
	// printf("%s\n", "s_opne Exiting");
	return fd;
}

/* SEEK_END should always return the file size
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);

	char path[100];
	memset(path,'\0',100);
	sprintf(path, "/proc/self/fd/%d", fd);
	char buff[100];
	memset(buff,'\0', sizeof(buff));
	readlink(path,buff, 100);
	char *token = strtok(buff,"/");
	while(token != NULL) {
		strcpy(buff, token);
		token = strtok(NULL,"/");
	}

	char pathname[32];
	memset(pathname, '\0', 32);
	strcpy(pathname, buff);


	if(whence == 2) {
		for(int i=0;i<numFs;++i) {
			if(strcmp(pathname, fs[i].filename) == 0)
				return fs[i].fileSize;
		}
	}

	return lseek (fd, offset, whence);
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */

ssize_t s_write (int fd, const void *buf, size_t count)
{
	assert (filesys_inited);

	// char path[32];
	// memset(path,'\0',32);
	// strcpy(path,"/proc/self/fd/");
	char path[100];
	memset(path,'\0',100);
	sprintf(path, "/proc/self/fd/%d", fd);
	char buff[100];
	memset(buff,'\0', sizeof(buff));
	readlink(path,buff, 100);
	char *token = strtok(buff,"/");
	while(token != NULL) {
		strcpy(buff, token);
		token = strtok(NULL,"/");
	}

	char securehash[21];
	memset(securehash,'\0',sizeof(securehash));
	char pathname[32], sha1[21];
	memset(pathname, '\0', 32);
	memset(sha1,'\0',21);
	strcpy(pathname, buff);
	// printf("PATH = %s\n",path );
	buildMerkle(pathname, sha1);
	int flag = -1;
	for(int i=0;i<numFs;++i) {
		if(strcmp(pathname, fs[i].filename) == 0) {
			strcpy(fs[i].sha,sha1);
			flag = i;
			break;
		}
	}
	if(flag == -1) {
		//printf("PATH = %s\n",path );
		//printf("%d\n", fd);
		//printf("%s\n", "unable to find the merkle tree, open the file again");
		return -1;
	}

	// printf("FILENAME IN SWRITE = %s\n", pathname);
	if(get_entry(pathname, securehash) != 1) {
		// printf("Securehash in swrite = %s\n", securehash);
		//printf("s_write : securehash doesn't exist\n");
		return -1;
	}

	// printf("check integrity = %s %s\n", securehash, sha1);
	lseek(fd,0,SEEK_END);
	if(checkIntegrity(securehash, sha1) == -1) {
		//printf("ERRRROOOORR s_write L integrity failed\n");
		return -1;
	}

	ssize_t retVal = write (fd, buf, count);
	// fsync(fd);
	// printf("s_write , write:  %ld\n", retVal);

	char newsha[21];
	memset(newsha,'\0',sizeof(newsha));
	buildMerkle(pathname, newsha);
	// printf("NEW SHA === %s\n", newsha);
	// printf("OLD SHA === %s\n", fs[flag].sha);

	memset(fs[flag].sha,'\0',sizeof(fs[flag].sha));
	strcpy(fs[flag].sha, newsha);
	lseek(fd,0,SEEK_SET);
	fs[flag].fileSize = lseek(fd,0,SEEK_END);
	lseek(fd,0,SEEK_SET);

	// printf("NEW SHA === %s\n", fs[flag].sha);

	update_entry(pathname, newsha);
	// printf("%s\n", "S_WRITE EXITING!!!");

	return retVal;
}

/* check the integrity of blocks containing the
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);

	char path[100];
	memset(path,'\0',100);
	sprintf(path, "/proc/self/fd/%d", fd);
	char buff[100];
	memset(buff,'\0', sizeof(buff));
	readlink(path,buff, 100);
	char *token = strtok(buff,"/");
	while(token != NULL) {
		strcpy(buff, token);
		token = strtok(NULL,"/");
	}

	char pathname[32];
	memset(pathname, '\0', 32);
	strcpy(pathname, buff);

	int fd1 = s_open (pathname, O_RDONLY, 0);

	if (fd1 == -1) {
		return -1;
	}
	s_close(fd1);

	ssize_t readret = read (fd, buf, count);
	return readret;
}

/* destroy the in-memory Merkle tree */
int s_close (int fd)
{
	assert (filesys_inited);
	return close (fd);
}

/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{
	for(int i=0;i<1;++i) {
		memset(fs[i].filename,'\0',sizeof(fs[i].filename));
		memset(fs[i].sha,'\0',sizeof(fs[i].sha));
		fs[i].fileSize = 0;
	}
	if(access("secure.txt", F_OK ) != -1 ) {
		filesys_inited = 1;
		//printf("%s\n","secure.txt exists");
		char line[256],line2[256];
		memset(line,'\0',256);
		memset(line2,'\0',256);

		FILE *fp1 = fopen("secure.txt","r");
		FILE *tempfp = fopen("tempsecure.txt","w");

		while (fgets(line,sizeof line,fp1) != NULL)
		{
			if( line != NULL || line[0] !='\n' )
			{
				strcpy(line2, line);
				char* rest = NULL;
				char* filename = strtok_r(line, " ",&rest);

				if(access(filename, F_OK) != -1) {

					char sha1[21];
					memset(sha1,'\0',sizeof(sha1));
					for(int i=0;i<20;++i) {
						sha1[i] = *rest;
						rest++;
					}
					strcpy(fs[numFs].filename,filename);
					strcpy(fs[numFs].sha,sha1);
					++numFs;
					//printf("%s %s %s\n", "File to be check exists", sha1, filename);
					int b = s_open(filename,O_WRONLY,0);
					if(b == -1){
						return 1;
					}
					else {
						fs[numFs-1].fileSize = lseek(b,0,SEEK_END);
						lseek(b,0,SEEK_SET);lseek(b,0,SEEK_END);
						close(b);
					}

					fputs(line2,tempfp);
					// fflush(tempfp);
				}
				else {
					//printf("%s\n", "File doesn't exist dont add");
				}
				memset(line,'\0',256);
				memset(line2,'\0',256);
			}
			else
			{
				//printf(" Found an empty Line which I should NOt have \n");
			}
		}

		fclose(tempfp);
		fclose(fp1);
		remove("secure.txt");
		if(rename("tempsecure.txt","secure.txt") == 0){
			// printf("Renamed tempsecure Successfully\n");
		}
	}
	else {
		//printf("%s\n","secure.txt Does not exist , Creating it......");
		FILE * fp;
		fp = fopen ("secure.txt", "w+");
		fclose(fp);
		return filesys_init();
	}

	filesys_inited = 1;
	return 0;
}
