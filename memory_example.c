#include <stdio.h>
#include <stdlib.h>

// Simple structure to demonstrate
struct Person {
    int age;           // 4 bytes
    double height;     // 8 bytes
    char name[50];     // 50 bytes
};

// Function that takes pointer (passes address - 8 bytes)
void with_pointer(struct Person* person) {
    printf("\n=== Using Pointer ===\n");
    printf("Address of person pointer: %p\n", (void*)&person);
    printf("Value inside pointer (address it points to): %p\n", (void*)person);
    printf("Size of pointer: %lu bytes\n", sizeof(person));
    
    // We can access the data through pointer
    printf("\nAccessing data through pointer:\n");
    printf("Age: %d\n", person->age);
    printf("Height: %.2f\n", person->height);
    printf("Name: %s\n", person->name);
}

// Function that takes structure by value (copies entire structure)
void without_pointer(struct Person person) {
    printf("\n=== Without Pointer (By Value) ===\n");
    printf("Address of person copy: %p\n", (void*)&person);
    printf("Size of entire structure: %lu bytes\n", sizeof(person));
    
    // We work with a copy of the data
    printf("\nAccessing copied data:\n");
    printf("Age: %d\n", person.age);
    printf("Height: %.2f\n", person.height);
    printf("Name: %s\n", person.name);
}

int main() {
    // Create a person structure
    struct Person john = {
        .age = 30,
        .height = 1.75,
        .name = "John Doe"
    };
    
    printf("=== Original Person ===\n");
    printf("Address of original person: %p\n", (void*)&john);
    printf("Size of person structure: %lu bytes\n", sizeof(struct Person));
    
    // Memory layout of the structure
    printf("\nMemory layout of person structure:\n");
    printf("age (4 bytes)    at address: %p\n", (void*)&john.age);
    printf("height (8 bytes) at address: %p\n", (void*)&john.height);
    printf("name (50 bytes)  at address: %p\n", (void*)&john.name);
    
    // Call both functions
    with_pointer(&john);    // Pass 8-byte address
    without_pointer(john);  // Pass entire structure
    
    return 0;
} 