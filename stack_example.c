#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_STACK_SIZE 100
#define MAX_WORD_LENGTH 20

// Stack structure
typedef struct
{
    char *items[MAX_STACK_SIZE]; // Array to store words
    int top;                     // Top of stack
} Stack;

// Initialize stack
void init_stack(Stack *s)
{
    s->top = -1; // Empty stack has top as -1
}

// Check if stack is full
int is_full(Stack *s)
{
    return s->top >= MAX_STACK_SIZE - 1;
}

// Check if stack is empty
int is_empty(Stack *s)
{
    return s->top < 0;
}

// Push word to stack
void push(Stack *s, const char *word)
{
    if (is_full(s))
    {
        printf("Stack overflow! Cannot push '%s'\n", word);
        return;
    }

    // Allocate memory for the word and copy it
    s->items[++(s->top)] = strdup(word);
    printf("Pushed: %s\n", word);
}

// Pop word from stack
char *pop(Stack *s)
{
    if (is_empty(s))
    {
        printf("Stack is empty!\n");
        return NULL;
    }
    return s->items[(s->top)--];
}

// Print stack contents
void print_stack(Stack *s)
{
    printf("\nStack contents (bottom to top):\n");
    for (int i = 0; i <= s->top; i++)
    {
        printf("%d: %s\n", i, s->items[i]);
    }
    printf("\n");
}

// Free stack memory
void free_stack(Stack *s)
{
    while (!is_empty(s))
    {
        char *word = pop(s);
        free(word);
    }
}

int main()
{
    Stack stack;
    init_stack(&stack);

    // Push "Hello World!" word by word
    printf("=== Pushing words onto stack ===\n");
    push(&stack, "Hello");
    push(&stack, "World!");

    // Print current stack state
    print_stack(&stack);

    // Pop and print words in reverse order (LIFO - Last In First Out)
    printf("=== Popping words from stack ===\n");
    while (!is_empty(&stack))
    {
        char *word = pop(&stack);
        printf("Popped: %s\n", word);
        free(word); // Free the memory allocated for the word
    }

    printf("\n=== Adding more words ===\n");
    // Add more words to demonstrate stack behavior
    push(&stack, "This");
    push(&stack, "is");
    push(&stack, "a");
    push(&stack, "stack");
    push(&stack, "example!");

    print_stack(&stack);

    // Clean up
    free_stack(&stack);

    return 0;
}