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
	HashTable *table = (HashTable*)malloc(sizeof(HashTable));
	for (int i=0;i<TABLE_SIZE;i++) {
		table->arr[i] = NULL;
	}
	return table;
}

int hash(int width, int height, int depth) {
	// Prime numbers to distribute values
	// TODO: fix possibility for collisions
	unsigned int hash = 17;
    hash = hash * 31 + width;
    hash += 31 + height;
    hash += 31 + depth;

	return hash % TABLE_SIZE;
}

int search(HashTable table, int width, int height, int depth) {
	int index = hash(width, height, depth);
	Node *node = table->arr[index];

	while (node->key != NULL) {
		if (	node->width == width && 
				node->height == height &&
				node->depth == depth) {
			return 1;
		}
		node = node->next;
	}
	return 0;
}

void insert(HashTable table, int width, int height, int depth) {
	int index = hash(width, height, depth);
	Node *node = malloc(sizeof(Node));
	node->width = width;
	node->height = height;
	node->depth = depth;
	node->next = table->arr[index];
	table->arr[index] = node;
}
