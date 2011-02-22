#include <stdio.h>
#include <stdlib.h>

int main (int argc, char **argv)
{
	int i;
	
	printf ("main: 0x%08X\n", (unsigned int)main);

	for (i = 0; i < argc; i++)
		printf ("argv[%d] = %s\n", i, argv[i]);

	return 0;
}
