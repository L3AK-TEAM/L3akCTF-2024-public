#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>

FILE *choncc_file_stream = NULL;
size_t allowed_total_size = 0x200;

typedef struct __choncc {
	size_t sz;
	char *str;
	struct __choncc *next;
} choncc;

choncc *head;

void open_chonccfile() {
	puts("Opening chonccfile...");
	choncc_file_stream = fopen("/tmp/chonccfile", "w");
	puts("Done");
}

void close_chonccfile() {
	puts("Closing chonccfile");
	if (choncc_file_stream != NULL) {
		fclose(choncc_file_stream);
	}
	for (int i = 0; i < 0x1d0; i += sizeof(int)) {
		usleep(rand() % 100000);
		*(int *)(((unsigned char *)choncc_file_stream) + i) ^= rand();
	}
	puts("Done");
}

void save_chonccfile() {
	printf("Writing to chonccfile at timestamp %llu...\n", time(NULL));
	puts("Are you sure you want to save? [Y/n]");
	char choice[0x20];
	fgets(choice, 0x10, stdin);
	if (tolower(choice[0]) == 'n') {
		puts("Writing chonccfile cancelled. Feel free to make more edits");
		return;
	}
	if (choncc_file_stream == NULL) {
		puts("Chonccfile is not even opened. What are you doing, my friend?");
	}
	choncc *cur = head;
	while (cur != NULL) {
		fwrite(&cur->sz, 4, 1, choncc_file_stream);
		fwrite(cur->str, cur->sz, 1, choncc_file_stream);
		cur = cur->next;
	}
	puts("Done");
}

void print_choncc() {
	puts("Enter the choncc number:");
	char input_buf[10];
	fgets(input_buf, 10, stdin);
	int idx = atoi(input_buf);
	if (idx <= 0) {
		puts("huh");
		return;
	}
	choncc *cur = head;
	int tmp_idx = 1;
	while (cur != NULL) {
		if (tmp_idx == idx) {
			break;
		}
		tmp_idx++;
		cur = cur->next;
	}
	if (cur == NULL) {
		puts("The choncc you wish to view does not exist.");
		return;
	}
	printf("%d: ", idx);
	write(STDOUT_FILENO, cur->str, cur->sz);
	write(STDOUT_FILENO, "\n", 1);
	puts("Done");
}

void edit_choncc() {
	puts("Enter the choncc number:");
	char input_buf[10];
	fgets(input_buf, 10, stdin);
	int idx = atoi(input_buf);
	if (idx <= 0) {
		puts("huh");
		return;
	}
	choncc *cur = head;
	int tmp_idx = 1;
	while (cur != NULL) {
		if (tmp_idx == idx) {
			break;
		}
		tmp_idx++;
		cur = cur->next;
	}
	if (cur == NULL) {
		puts("The choncc you wish to edit does not exist.");
		return;
	}
	puts("Enter the new content for the choncc:");
	read(STDIN_FILENO, cur->str, cur->sz);
	puts("Done");
}

void add_choncc() {
	puts("Enter the size of the choncc:");
	char input_buf[10];
	fgets(input_buf, 10, stdin);
	int size = atoi(input_buf);
	if (size <= 0) {
		puts("huh");
		return;
	}

	if (size > allowed_total_size) {
		puts("that's too much");
		return;
	}
	allowed_total_size -= size;

	choncc *ptr = malloc(sizeof(choncc));
	ptr->sz = size;
	ptr->str = malloc(size);
	ptr->next = NULL;

	if (head == NULL) {
		head = ptr;
		return;
	}
	choncc *cur = head;
	while (cur->next != NULL) {
		cur = cur->next;
	}
	cur->next = ptr;
	puts("Done");
}

void remove_choncc() {
	if (head == NULL) {
		puts("You have no chonccs to remove");
		return;
	}
	puts("Enter the choncc number:");
	char input_buf[10];
	fgets(input_buf, 10, stdin);
	int idx = atoi(input_buf);
	if (idx <= 0) {
		puts("huh");
		return;
	}
	choncc *tmp = NULL;
	if (head != NULL && idx == 1) {
		tmp = head;
		head = head->next;
	} else {
		choncc *par = NULL;
		par = head;
		int cur_idx = 2;
		while (par->next != NULL && cur_idx != idx) {
			par = par->next;
			cur_idx++;
		}
		if (cur_idx != idx || par->next == NULL) {
			puts("The choncc you wish to remove does not exist.");
			return;
		}
		tmp = par->next;
		par->next = par->next->next;
	}
	allowed_total_size += tmp->sz;
	free(tmp->str);
	free(tmp);
	puts("Done");
}

void menu() {
	puts("1. Create a choncc");
	puts("2. View a choncc");
	puts("3. Edit a choncc");
	puts("4. Remove a choncc");
	puts("5. Open  the chonccfile");
	puts("6. Close the chonccfile");
	puts("7. Write to the chonccfile");
	puts("8. Quit");
	printf("> ");
}

int main() {
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	srand(time(NULL));
	int running = 1;
	while (running) {
		menu();
		char input_buf[10];
		fgets(input_buf, 10, stdin);
		int choice = atoi(input_buf);
		switch(choice) {
			case 1:
				add_choncc();
				break;
			case 2:
				print_choncc();
				break;
			case 3:
				edit_choncc();
				break;
			case 4:
				remove_choncc();
				break;
			case 5:
				open_chonccfile();
				break;
			case 6:
				close_chonccfile();
				break;
			case 7:
				save_chonccfile();
				break;
			case 8:
				running = 0;
				break;
			default:
				puts("what options are you making up?");
				break;
		}
	}
	return 0;
}
