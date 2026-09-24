#include <stdio.h>
#include <windows.h>
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
} OBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION {
    ULONG NumberOfTypes;
    OBJECT_TYPE_INFORMATION TypeInformation[1];
} OBJECT_TYPES_INFORMATION;

int main() {
    printf("sizeof UNICODE_STRING: %lu\n", sizeof(UNICODE_STRING));
    printf("sizeof OBJECT_TYPE_INFORMATION: %lu\n", sizeof(OBJECT_TYPE_INFORMATION));
    printf("sizeof OBJECT_TYPES_INFORMATION: %lu\n", sizeof(OBJECT_TYPES_INFORMATION));
    printf("offset of TypeInformation: %lu\n", offsetof(OBJECT_TYPES_INFORMATION, TypeInformation));
    return 0;
}
