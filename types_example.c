#include <stdio.h>
#include <stdint.h>  // For fixed-width integer types

// 1. typedef for basic types
typedef unsigned char byte;      // Create an alias for unsigned char
typedef unsigned int uint;       // Create an alias for unsigned int

// 2. typedef with struct
typedef struct {
    int x;
    int y;
} Point;  // Now we can use 'Point' instead of 'struct Point'

// 3. typedef for function pointers
typedef void (*CallbackFunc)(int);  // Type for a function that takes int and returns void

// 4. typedef for arrays
typedef int Array5[5];  // Type for array of 5 integers

// 5. enum definition
typedef enum {
    SUCCESS = 0,
    ERROR_FILE_NOT_FOUND = -1,
    ERROR_NO_PERMISSION = -2,
    ERROR_INVALID_INPUT = -3
} StatusCode;

// 6. union definition
typedef union {
    int as_int;
    float as_float;
    char as_bytes[4];
} DataConverter;  // Useful for type punning and data conversion

// 7. Complex structure with nested types
typedef struct {
    byte id;                    // Using our typedef
    Point position;             // Using previously defined type
    StatusCode status;          // Using enum type
    CallbackFunc on_update;     // Using function pointer type
    Array5 data;               // Using array type
} Entity;

// Example callback function
void print_number(int n) {
    printf("Number: %d\n", n);
}

int main() {
    // Using basic typedef
    byte b = 255;
    printf("byte value: %u\n", b);
    
    // Using Point struct
    Point p = {10, 20};
    printf("Point: (%d, %d)\n", p.x, p.y);
    
    // Using function pointer type
    CallbackFunc func = print_number;
    func(42);
    
    // Using array typedef
    Array5 numbers = {1, 2, 3, 4, 5};
    printf("Third number: %d\n", numbers[2]);
    
    // Using enum
    StatusCode code = SUCCESS;
    printf("Status code: %d\n", code);
    
    // Using union for type conversion
    DataConverter converter;
    converter.as_float = 3.14f;
    printf("Float as int: %d\n", converter.as_int);
    printf("Float as bytes: ");
    for(int i = 0; i < 4; i++) {
        printf("%02x ", (unsigned char)converter.as_bytes[i]);
    }
    printf("\n");
    
    // Using complex structure
    Entity entity = {
        .id = 1,
        .position = {100, 200},
        .status = SUCCESS,
        .on_update = print_number
    };
    
    printf("\nEntity:\n");
    printf("ID: %u\n", entity.id);
    printf("Position: (%d, %d)\n", entity.position.x, entity.position.y);
    printf("Status: %d\n", entity.status);
    entity.on_update(123);
    
    // 8. Fixed-width integer types (from stdint.h)
    uint8_t  byte_val = 255;    // Exactly 8 bits
    uint16_t word_val = 65535;  // Exactly 16 bits
    uint32_t dword_val = 4294967295u;  // Exactly 32 bits
    int64_t  qword_val = 9223372036854775807LL;  // Exactly 64 bits
    
    printf("\nFixed-width types:\n");
    printf("uint8_t:  %u\n", byte_val);
    printf("uint16_t: %u\n", word_val);
    printf("uint32_t: %u\n", dword_val);
    printf("int64_t:  %lld\n", qword_val);
    
    return 0;
} 