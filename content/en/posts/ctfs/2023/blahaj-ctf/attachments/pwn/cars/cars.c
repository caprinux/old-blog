#include <stdio.h>
#include <stdlib.h>

// Compiled using gcc -o cars -g -fno-stack-protector cars.c

unsigned long report_number = 0;

void setup()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void file_report()
{
    char input[28];
    printf("Please input your student ID: ");
    fgets(input, 28, stdin);
    printf("Please describe the incident: ");
    fgets(input, 256, stdin);
    printf("The matter has been recorded and will be investigated. Thank you.\n");
}

void admin()
{
    // how did you even get here?
    FILE *fptr = fopen("flag", "r");
    if (fptr == NULL)
    {
        printf("Cannot open flag\n");
        exit(0);
    }
    char c;
    while ((c = fgetc(fptr)) != EOF)
    {
        printf("%c", c);
    }
    fclose(fptr);
}

int main()
{
    setup();
    srand(0xb1adee); // this random seed is sooo drain
    report_number = rand();
    printf("Welcome to the Cyber Affairs Reporting System (CARS)\n");
    printf("Report number: #%lu\n", &report_number);
    file_report();
    return 0;
}
