/*
 *  Common functions for all aircrack-ng tools
 *
 *  Copyright (C) 2006, 2007, 2008 Thomas d'Otreppe
 *
 *  WEP decryption attack (chopchop) developped by KoreK
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>

#define isHex(c) (hexToInt(c) != -1)
#define HEX_BASE 16

/* Return the version number */
char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc)
{
	int len;
	char * temp;
	char * provis = calloc(1,20);
	len = strlen(progname) + 200;
	temp = (char *) calloc(1,len);

	snprintf(temp, len, "%s %d.%d", progname, maj, min);

	if (submin > 0) {
		snprintf(provis, 20,".%d",submin);
		strncat(temp, provis, len - strlen(temp));
		memset(provis,0,20);
	}

	if (rc > 0) {
		snprintf(provis, 20, " rc%d", rc);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, 20);
	} else if (beta > 0) {
		snprintf(provis, 20, " beta%d", beta);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, 20);
	}

	if (svnrev > 0) {
		snprintf(provis, 20," r%d",svnrev);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, 20);
	}

	free(provis);
	temp = realloc(temp, strlen(temp)+1);
	return temp;
}

// Return the number of cpu. If detection fails, it will return -1;
int get_nb_cpus()
{
		// Optmization for windows: use GetSystemInfo()
        char * s, * pos;
        FILE * f;
        int number = -1;

		// Reading /proc/cpuinfo is more reliable on current CPUs,
		// so put it first and try the old method if this one fails
        f = fopen("/proc/cpuinfo", "r");
        if (f != NULL) {
				s = (char *)calloc(1, 81);
				if (s != NULL) {
					// Get the latest value of "processor" element
					// and increment it by 1 and it that value
					// will be the number of CPU.
					number = -2;
					while (fgets(s, 80, f) != NULL) {
							pos = strstr(s, "processor");
							if (pos == s) {
									pos = strchr(s, ':');
									number = atoi(pos + 1);
							}
					}
					++number;
					free(s);
				}
				fclose(f);
        }

        #ifdef _SC_NPROCESSORS_ONLN
        // Try the usual method if _SC_NPROCESSORS_ONLN exist
        if (number == -1) {

			number   = sysconf(_SC_NPROCESSORS_ONLN);
			/* Fails on some archs */
			if (number < 1) {
				number = -1;
			}
        }
        #endif

        return number;
}

/* Check if we are running on a Cell Broadband Engine.
 * Returns the number of SPEs, or -1 if not running on Cell. */
int get_cell_nb_spes(void)
{
	FILE *f;
	char *s, *pos;

#ifndef HAVE_CELL
	return -1;
#endif

	f = fopen("/proc/cpuinfo", "r");
	if (!f)
		return -1;
	s = calloc(1, 81);
	if (!s) {
		fclose(f);
		return -1;
	}
	while (fgets(s, 80, f)) {
		pos = strstr(s, "Cell Broadband Engine");
		if (pos) {
			fclose(f);
			free(s);
			return 6;
		}
	}
	fclose(f);
	free(s);

	return -1;
}

//compares two MACs
int maccmp(unsigned char *mac1, unsigned char *mac2)
{
    int i=0;

    if(mac1 == NULL || mac2 == NULL)
        return -1;

    for(i=0; i<6; i++)
    {
        if( toupper(mac1[i]) != toupper(mac2[i]) )
            return -1;
    }
    return 0;
}

// Converts a mac address in a human-readable format
char * mac2string(unsigned char *mac_address )
{
	char * mac_string = (char *)malloc(sizeof(char)*18);
	sprintf(mac_string, "%02X:%02X:%02X:%02X:%02X:%02X", *mac_address,
						*(mac_address+1), *(mac_address+2), *(mac_address+3),
						*(mac_address+4), *(mac_address+5));
	return mac_string;
}

/* Return -1 if it's not an hex value and return its value when it's a hex value */
int hexCharToInt(unsigned char c)
{
	static int table_created = 0;
	static int table[256];

	int i;

	if (table_created == 0)
	{
		/*
		 * It may seem a bit long to calculate the table
		 * but character position depend on the charset used
		 * Example: EBCDIC
		 * but it's only done once and then conversion will be really fast
		 */
		for (i=0; i < 256; i++)
		{

			switch ((unsigned char)i)
			{
				case '0':
					table[i] = 0;
					break;
				case '1':
					table[i] = 1;
					break;
				case '2':
					table[i] = 2;
					break;
				case '3':
					table[i] = 3;
					break;
				case '4':
					table[i] = 4;
					break;
				case '5':
					table[i] = 5;
					break;
				case '6':
					table[i] = 6;
					break;
				case '7':
					table[i] = 7;
					break;
				case '8':
					table[i] = 8;
					break;
				case '9':
					table[i] = 9;
					break;
				case 'A':
				case 'a':
					table[i] = 10;
					break;
				case 'B':
				case 'b':
					table[i] = 11;
					break;
				case 'C':
				case 'c':
					table[i] = 12;
					break;
				case 'D':
				case 'd':
					table[i] = 13;
					break;
				case 'E':
				case 'e':
					table[i] = 14;
					break;
				case 'F':
				case 'f':
					table[i] = 15;
					break;
				default:
					table[i] = -1;
			}
		}

		table_created = 1;
	}

	return table[c];
}

int hexStringToHex(char* in, int length, unsigned char* out)
{
    int i=0;
    int char1, char2;

    char *input=in;
    unsigned char *output=out;

    if(length < 1)
        return 1;

    for(i=0; i<length; i+=2)
    {
        if(input[i] == '-' || input[i] == ':' || input[i] == '_' || input[i] == ' ')
        {
            input++;
            length--;
        }
        char1 = hexCharToInt(input[i]);
        char2 = hexCharToInt(input[i+1]);
        if(char1 < 0 || char1 > 15)
            return -1;
        output[i/2] = ((char1 << 4) + char2) & 0xFF;
    }
    return (i/2);
}

//Return the mac address bytes (or null if it's not a mac address)
int getmac(char * macAddress, int strict, unsigned char * mac)
{
	char byte[3];
	int i, nbElem, n;

	if (macAddress == NULL)
		return 1;

	/* Minimum length */
	if ((int)strlen(macAddress) < 12)
		return 1;

	memset(mac, 0, 6);
	byte[2] = 0;
	i = nbElem = 0;

	while (macAddress[i] != 0)
	{
		byte[0] = macAddress[i];
		byte[1] = macAddress[i+1];

		if (sscanf( byte, "%x", &n ) != 1
			&& strlen(byte) == 2)
			return 1;

		if (hexCharToInt(byte[1]) < 0)
			return 1;

		mac[nbElem] = n;

		i+=2;
		nbElem++;

		if (macAddress[i] == ':' || macAddress[i] == '-'  || macAddress[i] == '_')
			i++;
	}

	if ((strict && nbElem != 6)
		|| (!strict && nbElem > 6))
		return 1;

	return 0;
}

// Read a line of characters inputted by the user
int readLine(char line[], int maxlength)
{
	int c;
	int i = -1;

	do
	{
		// Read char
		c = getchar();

		if (c == EOF)
			c = '\0';

		line[++i] = (char)c;

		if (line[i] == '\n')
			break;
		if (line[i] == '\r')
			break;
		if (line[i] == '\0')
			break;
	}
	while (i + 1 < maxlength);
	// Stop at 'Enter' key pressed or EOF or max number of char read

	// Return current size
    return i;
}

int hexToInt(char s[], int len)
{
	int i = 0;
	int convert = -1;
	int value = 0;

	// Remove leading 0 (and also the second char that can be x or X)

	while (i < len)
	{
		if (s[i] != '0' || (i == 1 && toupper((int)s[i]) != 'X'))
			break;

		++i;
	}

	// Convert to hex

	while (i < len)
	{
		convert = hexCharToInt((unsigned char)s[i]);

		// If conversion failed, return -1
		if (convert == -1)
			return -1;

		value = (value * HEX_BASE) + convert;

		++i;
	}


	return value;
}
