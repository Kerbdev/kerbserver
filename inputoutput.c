
#include <stdio.h>
#include <stdlib.h>
FILE *openfile(char* fname, char* permissions)
{
	FILE *db;
	db = fopen(fname, permissions);
	return db;
}
void filewrite(char* fname, char* from_buf,...)
{
	FILE *filename;
	filename = openfile(fname,"at");
	char **cp = &from_buf;
	while (*cp)
	{
		fprintf(filename, "%s; ", *cp);
		cp++;
	}
	fclose(filename);
}
void fileread(char* fname)
{
	char ch;
	int charnum = 0;
	char* Str = (char*)malloc(sizeof(char));
	FILE *db = openfile(fname,"r");
	int memsize = sizeof(char);

	while ((ch = getc(db)) != EOF)
	{
		Str[charnum] = ch;
		charnum++;
		memsize += sizeof(char);
		Str = (char*)realloc(Str, memsize);
	}
	Str[charnum] = '\0';
	printf("%s", Str);
}
