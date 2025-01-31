#include <stdio.h>
#include <stdlib.h>

#define TABLE_SIZE 1000

typedef struct Node {
	int width;
	int height;
	int depth;
	struct Node *next;
} Node;

typedef struct HashTable {
	Node *arr[TABLE_SIZE];
} HashTable;


HashTable *create_table(int length) {
}

int hash(int width, int height, int depth) {
}

int search(HashTable table, int width, int height, int depth) {
}

void insert(HashTable table, int width, int height, int depth) {
}
