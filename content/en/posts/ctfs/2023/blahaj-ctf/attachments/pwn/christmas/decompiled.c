#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>


int main()
{
  int64_t choice;
  int64_t idx;
  unsigned idxa;
  unsigned idxb;
  int64_t size;
  char *wishlist[10];
  char buf[128];

  memset(wishlist, 0, sizeof(wishlist));
  setup();
  print_banner();

  while (1) {

    print_menu();
    fgets(buf, 128, stdin);
    choice = atoi(buf);

    switch (choice) {
      case 1:  // add wish
        puts("There's just one thing I need");
        printf("> ");
        fgets(buf, 128, stdin);
        idx = atoi(buf);
        if ( idx >= 10 )
          printf("Don't care about the presents underneath %ld and %ld\n", 0LL, 9LL);
        puts("I won't ask for much this Christmas");
        printf("> ");
        fgets(buf, 128, stdin);
        size = atoi(buf);
        if ( size >= 0 ) {
          wishlist[idx] = malloc(size);
          puts("All I want for Christmas is");
          printf("> ");
          fgets(wishlist[idx], size, stdin);
        }
        else {
          puts("Invalid size");
        }
        break;
      case 2:   // remove wish
        puts("I won't make a list");
        printf("> ");
        fgets(buf, 128, stdin);
        idxa = atoi(buf);
        if ( idxa >= 0xA )
          printf("Don't care about the presents underneath %ld and %ld\n", 0LL, 9LL);
        free(wishlist[idxa]);
        wishlist[idxa] = 0LL;
        break;
      case 3:   // view wish
        puts("Make my wish come true");
        printf("> ");
        fgets(buf, 128, stdin);
        idxb = atoi(buf);
        if ( idxb >= 0xA ) {
          printf("Don't care about the presents underneath %ld and %ld\n", 0LL, 9LL);
        }
        else if ( wishlist[idxb] ) {
          puts("All I want for Christmas is");
          puts(wishlist[idxb]);
        }
        else {
          puts("Santa, won't you bring me the one I really need?");
        }
        break;
      case 4:   // exit
        bye();
        exit(0);
      default:
        continue;
    }
  }
}
