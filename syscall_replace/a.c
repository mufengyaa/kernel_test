#include <stdio.h>

int main()
{
    while (1)
    {
        int x = 1, y = 1;
        int ret = x * y;
        ++x;
        ++y;
    }
    return 0;
}