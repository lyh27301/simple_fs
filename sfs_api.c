#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include "disk_emu.h"

// Create stucture for different table enries
typedef struct superblock
{
    int magic;
    int block_size;
    int fs_size;
    int inode_table_length;
    int root_dir_inode_index;
} superblock;

typedef struct
{
    int size;
    int data_ptrs[12];
    int indirectPointer; // point to a block that points to another block
} iNode;

typedef struct
{
    char *file_name;
    int iNode_index;
} directory_entry;

typedef struct
{
    int inode_index;
    iNode *inode_ptr;
    int read_ptr;
    int write_ptr;
} file_descriptor_entry;

superblock sb;

// Constant list
#define MAXFILENAME 16
#define MAX_EXTENSION 3
#define BLOCK_SIZE 1024                                                            // The size of one data block, also the size of a sector (a fixed size block), 1024 bytes
#define NUM_BLOCKS 1024                                                            // The number of data blocks on the disk.
#define NUM_DATA_BLOCK (NUM_BLOCKS - NUM_INODE_BLOCKS - NUM_SUPERBLOCK_BLOCKS - 1) // 1 is for bitmap (i024 char entries take 1024 byte, which eqauls the size of one block)
#define NUM_INODES 1024
#define NUM_FILES ((NUM_INODES)-1)
#define NUM_INODE_BLOCKS (sizeof(iNode) * NUM_INODES / BLOCK_SIZE + (sizeof(iNode) * NUM_INODES % BLOCK_SIZE != 0)) // Number of blocks used by all inode
#define NUM_SUPERBLOCK_BLOCKS (sizeof(superblock) / BLOCK_SIZE + (sizeof(superblock) % BLOCK_SIZE != 0))
#define DATA_BLOCK_START (NUM_INODE_BLOCKS + NUM_SUPERBLOCK_BLOCKS + 1) // 1 is for bitmap (i024 char entries take 1024 byte, which eqauls the size of one block)
#define DISK_NAME "sfs_disk.disk"
#define NUM_FILE_LIST_BLOCKS (sizeof(directory_entry) * NUM_FILES / BLOCK_SIZE + (sizeof(directory_entry) * NUM_FILES % BLOCK_SIZE != 0))

// Free bitmap
char free_bitmap[NUM_BLOCKS]; // Each char represents the condition of a block: set to 0 if free; otherwise 1;

// Tables
file_descriptor_entry file_descriptor[NUM_INODES];
iNode iNode_table[NUM_INODES];
directory_entry file_list[NUM_FILES];

// File number record
int num_files = 0;

// Current file position index
int current_file = 0;

//Read buffer
void *buffer;

// Functions
void mksfs(int fresh);                             // Creates the file system
int sfs_getnextfilename(char *fname);              // Get the name of the next file in directory
int sfs_getfilesize(const char *path);             // Get the size of the next file in directory
int sfs_fopen(char *name);                         // Opens the given file
int sfs_fclose(int fileID);                        // Closes the given file
int sfs_frseek(int fileID, int loc);               // Seek (read) to the location from beginning
int sfs_fwseek(int fileID, int loc);               // Seek (write) to the location from beginning
int sfs_fwrite(int fileID, char *buf, int length); // Write buf characters into disk
int sfs_fread(int fileID, char *buf, int length);  // Read characters from disk into buf
int sfs_remove(char *file);                        // Removes a file from the filesystem

// Helper fuctions
void init_superblock();
void init_file_descripter();
void init_iNode_table();
void init_file_list();
int if_name_valid(const char *name);                                 // Return 0 if valid, otherwise return 1
int get_iNode_index_in_directory(directory_entry dir[], char *file); // Return the index of iNode if the file is found, otherwise return -1
int bitmap_occupy_one_bit();
void bitmap_free_one_bit(int i);
void set_index(int i);



void mksfs(int fresh)
{
    int disk;
    if (fresh)
    { // Create from scratch

        // If there is a disk, remove it
        remove(DISK_NAME);

        // Initialize a new disk
        disk = init_fresh_disk(DISK_NAME, BLOCK_SIZE, NUM_BLOCKS);
        if (disk != 0)
        {
            printf("Error: Failed to initialize disk\n");
        }

        // Initialize superblock
        init_superblock();

        // Write superblock to disk
        if (write_blocks(0, NUM_SUPERBLOCK_BLOCKS, (void *)(&sb)) < 0)
        {
            printf("Error: Failed to write superblock to disk\n");
        }

        // Initialize root inode and inode table
        init_iNode_table();

        // Write inode table to disk
        if (write_blocks(NUM_SUPERBLOCK_BLOCKS, NUM_INODE_BLOCKS, (void *)(&iNode_table)) < 0)
        {
            printf("Error: Failed to write iNode table to disk\n");
        }

        // Initialize file list
        init_file_list();

        // Write file list to disk
        if (write_blocks(DATA_BLOCK_START, NUM_FILE_LIST_BLOCKS, (void *)(&file_list)) < 0)
        {
            printf("Error: Failed to write file list to disk\n");
        }

        // Initialize file descriptor table in memory
        init_file_descripter();

        // Update free bitmap
        int used_blocks = NUM_SUPERBLOCK_BLOCKS + NUM_INODE_BLOCKS + NUM_FILE_LIST_BLOCKS + 1;
        for (int i; i < NUM_BLOCKS; i++)
        {
            if (i < used_blocks)
            {
                free_bitmap[i] = 1;
            }
            else
            {
                free_bitmap[i] = 0;
            }
        }
    }
    else
    { // open the sfs from the disk
        disk = init_disk(DISK_NAME, BLOCK_SIZE, NUM_BLOCKS);

        if (disk != 0)
        {
            printf("Error: Failed to initialize disk\n");
        }

        // Read free bitmap
        buffer = (void *)malloc(BLOCK_SIZE);
        memset(buffer, 1, BLOCK_SIZE);
        read_blocks(DATA_BLOCK_START - 1, DATA_BLOCK_START, buffer);
        memcpy(free_bitmap, buffer, NUM_BLOCKS);
        free(buffer);

        // Read superblock
        buffer = (void *)malloc(NUM_SUPERBLOCK_BLOCKS * BLOCK_SIZE);
        memset(buffer, 0, NUM_SUPERBLOCK_BLOCKS * BLOCK_SIZE);
        read_blocks(0, NUM_SUPERBLOCK_BLOCKS, buffer);
        memcpy(&sb, buffer, sizeof(superblock));
        free(buffer);
        set_index(0);

        // Read inode table
        buffer = (void *)malloc(NUM_INODE_BLOCKS * BLOCK_SIZE);
        memset(buffer, 0, NUM_INODE_BLOCKS * BLOCK_SIZE);
        read_blocks(1, NUM_INODE_BLOCKS, buffer);
        memcpy(iNode_table, buffer, NUM_INODES * sizeof(iNode));
        free(buffer);

        // Read file lisy (root)
        buffer = (void *)malloc(NUM_FILE_LIST_BLOCKS * BLOCK_SIZE);
        memset(buffer, 0, NUM_FILE_LIST_BLOCKS * BLOCK_SIZE);
        read_blocks(DATA_BLOCK_START, NUM_FILE_LIST_BLOCKS, buffer);
        memcpy(file_list, buffer, NUM_FILES * sizeof(directory_entry));
        free(buffer);

        // Initialize file descriptors in memory
        init_file_descripter();

        // Update the number of files
        for (int i = 0; i < NUM_FILES; i++)
        {
            if (file_list[i].iNode_index != -1)
            {
                num_files++;
            }
        }
    }

    return;
    if (disk != 0)
    {
        printf("Error: Failed to initialize disk\n");
    }

    return;
}

int sfs_getnextfilename(char *fname)
{
    // If no files, then no next file
    if (num_files == 0)
    {
        return 0;
    }

    //check if there is a new file
    if (current_file < NUM_FILES - 1)
    {
        for (int i = (current_file + 1); i < NUM_FILES; i++)
        {
            if (!strcmp(file_list[i].file_name, ""))
            { //check if the current position is empty
                strcpy(fname, file_list[i].file_name);
                current_file = i;
                return 1;
            }
        }
    }
    else
    { // Already at the end of the file_list
        return 0;
    }

    return 0;
}

int sfs_getfilesize(const char *path)
{
    // Check if the filename is valid
    if (if_name_valid(path))
    {
        printf("Error: Invalid file name\n");
        return -1;
    }
    // look for the file in file list by its name
    for (int i = 0; i < NUM_FILES; i++)
    {
        if (file_list[i].iNode_index != -1 && strcmp(file_list[i].file_name, path) == 0)
        {
            return iNode_table[file_list[i].iNode_index].size;
        }
    }

    // If the file does not exist
    printf("Error: File %s not found\n", path);
    return -1;
}

int sfs_fopen(char *name)
{
    // Check if the filename is valid
    if (if_name_valid(name))
    {
        printf("Error: Invalid file name\n");
        return -1;
    }

    int iNode_index = get_iNode_index_in_directory(file_list, name);

    if (iNode_index != -1)
    {
        // There is an existing file of the name given in the directory
        // Check if the file is already open
        for (int i = 0; i < NUM_INODES; i++)
        {
            if (file_descriptor[i].inode_index == iNode_index)
            {
                return i; // file already open
            }
        }

        // The existing file is not open
        // Look for an unused slot in file descriptor
        int fd_index = -1;
        for (int i = 1; i < NUM_INODES; i++)
        { // slot of index 0 stores the root
            if (file_descriptor[i].inode_index == -1)
            {
                fd_index = i; // Set file descriptor index
                break;
            }
        }
        if (fd_index == -1)
        {                                                        // fd is already full
            printf("Error: Open file descriptor table full.\n"); // Should not happen as the root directory capacity euals to the file descripter capacity
            return -1;
        }
        file_descriptor[fd_index].read_ptr = 0;
        file_descriptor[fd_index].write_ptr = iNode_table[iNode_index].size;
        file_descriptor[fd_index].inode_index = iNode_index;
        file_descriptor[fd_index].inode_ptr = &iNode_table[iNode_index];
        return fd_index;
    }
    else
    {
        // No file of the name given exists, so create a file of the name

        // Look for a  free slot in root direcory (file list)
        int file_index = -1;
        for (int i = 0; i < NUM_FILES; i++)
        {
            if (file_list[i].iNode_index != -1)
            {
                file_index = i;
                break;
            }
        }
        if (file_index == -1)
        {
            printf("Error: Root directory is full\n");
            return -1;
        }

        // Look for an unused inode
        iNode_index = -1;
        for (int i = 1; i < NUM_INODES; i++)
        {
            if (iNode_table[i].size == -1)
            {
                iNode_index = i;
                break;
            }
        }

        if (iNode_index < 0)
        {
            printf("Error: INode table is full\n");
            return -1;
        }
        strcpy(file_list[file_index].file_name, name);   // Copy filename to fileIndex.name
        file_list[file_index].iNode_index = iNode_index; // Store index of file to fileIndex.num
        iNode_table[iNode_index].size = 0;               // Value that determines inode is used

        // Write to disk
        // Write inode table to disk
        if (write_blocks(NUM_SUPERBLOCK_BLOCKS, NUM_INODE_BLOCKS, (void *)(&iNode_table)) < 0)
        {
            printf("Error: Failed to write iNode table to disk\n");
        }

        // Write file list to disk
        if (write_blocks(DATA_BLOCK_START, NUM_FILE_LIST_BLOCKS, (void *)(&file_list)) < 0)
        {
            printf("Error: Failed to write file list to disk\n");
        }
    
        // Look for an unused slot in file descriptor
        int fd_index = -1;
        for (int i = 1; i < NUM_INODES; i++)
        { // slot of index 0 stores the root
            if (file_descriptor[i].inode_index == -1)
            {
                fd_index = i; // Set file descriptor index
                break;
            }
        }
        if (fd_index == -1)
        {                                                        // fd is already full
            printf("Error: Open file descriptor table full.\n"); // Should not happen as the root directory capacity euals to the file descripter capacity
            return -1;
        }

        file_descriptor[fd_index].read_ptr = 0;
        file_descriptor[fd_index].write_ptr = iNode_table[iNode_index].size;
        file_descriptor[fd_index].inode_index = iNode_index;
        file_descriptor[fd_index].inode_ptr = &iNode_table[iNode_index];
        return fd_index;
    }
}

int sfs_fclose(int fileID)
{

    // Check if the ID is valid
    if (fileID <= 0 || fileID > NUM_FILES)
    { // 0 is reserved for root
        printf("Error: File ID %d is invalid\n", fileID);
        return -1;
    }

    // Check if file already closed
    if (file_descriptor[fileID].inode_index == -1)
    {
        printf("There's no open file to close with the given fileID\n");
        return -1;
    }

    file_descriptor[fileID] = (file_descriptor_entry){-1, NULL, 0, 0}; // Reset file descriptor
    return 0;
}

int sfs_frseek(int fileID, int loc)
{
    // Check if the ID is valid
    if (fileID <= 0 || fileID > NUM_FILES)
    { // 0 is reserved for root
        printf("Error: File ID %d is invalid\n", fileID);
        return -1;
    }

    // Check if the file is open
    if (file_descriptor[fileID].inode_index == -1)
    {
        printf("There's no match open file\n");
        return -1;
    }
    // Check if location valid
    if (loc > iNode_table[file_descriptor[fileID].inode_index].size - 1){
        printf("Error: Invalid location\n");
        return -1;
    }

    file_descriptor[fileID].read_ptr = loc;
}

int sfs_fwseek(int fileID, int loc)
{
    // Check if the ID is valid
    if (fileID <= 0 || fileID > NUM_FILES)
    { // 0 is reserved for root
        printf("Error: File ID %d is invalid\n", fileID);
        return -1;
    }

    // Check if the file is open
    if (file_descriptor[fileID].inode_index == -1)
    {
        printf("There's no match open file\n");
        return -1;
    }
    // Check if location valid
    if (loc > iNode_table[file_descriptor[fileID].inode_index].size){
        printf("Error: Invalid location\n");
        return -1;
    }

    file_descriptor[fileID].write_ptr = loc;

    return 0;
}

int sfs_fwrite(int fileID, char *buf, int length)
{
    // Check if the length is valid
    if (length < 0)
    {
        printf("Error: Length must be 0 or greater\n");
        return -1;
    }

    // Check the fileID is valid
    if (fileID <= 0 || fileID > NUM_INODES)
    {
        printf("Error: Invalid file ID\n");
        return -1;
    }

    // Check if the file exists
    if (file_descriptor[fileID].inode_index < 0)
    {
        printf("Error: File not open\n");
        return -1;
    }

    // Set up fd and inode
    file_descriptor_entry fd = file_descriptor[fileID];
    iNode inode = iNode_table[fd.inode_index];

    int bytes_written = 0;
    int bytes_to_write = length;
    int indirect_addr[((BLOCK_SIZE / sizeof(int)))];

    buffer = malloc(BLOCK_SIZE);
    memset(buffer, '\0', BLOCK_SIZE);
    int addresses[((BLOCK_SIZE / sizeof(int)))];
    memset(addresses, 0, ((BLOCK_SIZE / sizeof(int))));
    
    // blocks pointed by 12 data pointers are not enough, use the indirect pointer
    if ((inode.indirectPointer == -1) && (bytes_to_write + fd.write_ptr > 12 * BLOCK_SIZE))
    {
        inode.indirectPointer = bitmap_occupy_one_bit();
        for (int i = 0; i < ((BLOCK_SIZE / sizeof(int))); i++)
        {
            indirect_addr[i] = -1;
        }
    }
    else if (bytes_to_write + fd.write_ptr > 12 * BLOCK_SIZE)
    {
        memset(addresses, 0, BLOCK_SIZE);
        read_blocks(inode.indirectPointer, 1, addresses);
        memcpy(indirect_addr, addresses, BLOCK_SIZE);
    }

    int disk_index;

    // Loop block by block until nothing left to write
    while (bytes_to_write > 0)
    {
        int new_block = 0;

        // Clear buffer
        memset(buffer, '\0', BLOCK_SIZE);

        int cur_block = fd.write_ptr / BLOCK_SIZE;
        int loc = fd.write_ptr % BLOCK_SIZE;
        int block_amount_left;

        if (bytes_to_write > (BLOCK_SIZE - loc))
        {
            block_amount_left = BLOCK_SIZE - loc;
        }
        else
        {
            block_amount_left = bytes_to_write;
        }

        // If in indirect pointer
        if (cur_block > 11)
        {
            // Get which block in indirect pointer
            disk_index = indirect_addr[cur_block - 12];
            if (disk_index <= 0)
            {
                // Set up new block
                new_block = 1;
                disk_index = bitmap_occupy_one_bit();
                if (disk_index < 0)
                {
                    printf("Error: Invalid disk index\n");
                    return -1;
                }
                // Save new block in indirect pointer
                indirect_addr[cur_block - 12] = disk_index;
            }
         
        }
        else
        {   // If in direct data ptr
            
            disk_index = inode.data_ptrs[cur_block];
            if (disk_index <= 0)
            {
                // Set up a new block
                new_block = 1;
                disk_index = bitmap_occupy_one_bit;
                if (disk_index < 0)
                {
                    printf("Error: Disk is full\n");
                    return -1;
                }
                inode.data_ptrs[cur_block] = disk_index;
            }
        }

        memset(buffer, 0, BLOCK_SIZE);
        if (!new_block)
        {
            read_blocks(disk_index, 1, buffer);
        }

        memcpy(buffer + loc, buf, (size_t)block_amount_left);

        if (write_blocks(disk_index, 1, buffer) < 0)
        {
            printf("Error: Cannot write blocks\n");
            return -1;
        }

        fd.write_ptr += block_amount_left;
        bytes_written += block_amount_left;
        bytes_to_write -= block_amount_left;
        buf += block_amount_left;

        if (fd.write_ptr > inode.size)
        {
            inode.size = fd.write_ptr;
        }
    }

    if (inode.indirectPointer != -1)
    {
        memset(addresses, 0, BLOCK_SIZE);
        memcpy(addresses, indirect_addr, BLOCK_SIZE);
        write_blocks(inode.indirectPointer, 1, addresses);
    }

    // Update inode table and fd table
    iNode_table[fd.inode_index] = inode;
    file_descriptor[fileID] = fd;

    free(buffer);
    // Write inode table to disk
        if (write_blocks(NUM_SUPERBLOCK_BLOCKS, NUM_INODE_BLOCKS, (void *)(&iNode_table)) < 0)
        {
            printf("Error: Failed to write iNode table to disk\n");
        }

    
    // Write file list to disk
        if (write_blocks(DATA_BLOCK_START-1, 1, (void *)(&free_bitmap)) < 0)
        {
            printf("Error: Failed to write free bitmap to disk\n");
        }

    return bytes_written;
}

int sfs_fread(int fileID, char *buf, int length){
    // Check if the length is valid
    if (length < 0)
    {
        printf("Error: Length must be 0 or greater\n");
        return -1;
    }

    // Check the fileID is valid
    if (fileID <= 0 || fileID > NUM_INODES)
    {
        printf("Error: Invalid file ID\n");
        return -1;
    }

    // Check if the file exists
    if (file_descriptor[fileID].inode_index < 0)
    {
        printf("Error: File not open\n");
        return -1;
    }


    // Find fd and inode
    file_descriptor_entry fd = file_descriptor[fileID];
    iNode inode = iNode_table[fd.inode_index];


    // Check what is left to read
    int read = 0;
    int left;
    int indirect_addr[BLOCK_SIZE / sizeof(int)];

    if ((fd.read_ptr + length + 1) > inode.size) {
        left = inode.size - fd.read_ptr;
    } else {
        left = length;
    }

    memset(buffer, 0, BLOCK_SIZE);
    int addresses[BLOCK_SIZE / sizeof(int)];
    memset(addresses, 0, BLOCK_SIZE / sizeof(int)); // Set indirect pointer
    if ((inode.indirectPointer == -1) && (length + fd.read_ptr > 12 * BLOCK_SIZE)) {
        inode.indirectPointer = bitmap_occupy_one_bit;
        for (int i = 0; i < BLOCK_SIZE / sizeof(int); i++) {
            indirect_addr[i] = -1;
        }
    } else if (length + fd.read_ptr > 12 * BLOCK_SIZE) {
        memset(addresses, 0, BLOCK_SIZE);
        read_blocks(inode.indirectPointer, 1, addresses);
        memcpy(indirect_addr, addresses, BLOCK_SIZE);
    }

    // Loop though data blocks until length is satisfied
    while (left > 0) {
        // Get which block and which index inside the block
        int cur_block = fd.read_ptr / BLOCK_SIZE;
        int loc = fd.read_ptr % BLOCK_SIZE;

        int block_amount_left;
        int disk_index;
        // Determine what is left to read in block
        if (left > (BLOCK_SIZE - loc)) {
            block_amount_left = BLOCK_SIZE - loc;
        } else {
            block_amount_left = left;
        }

        // Clear buffer
        memset(buffer, '\0', BLOCK_SIZE);

        // Read from data pointer or indirect pointer
        if (cur_block > 11) {
            disk_index = indirect_addr[cur_block - 12];
        } else {
            disk_index = inode.data_ptrs[cur_block];
        }

        if (read_blocks(disk_index, 1, buffer) < 0) {
            printf("Error: Cannot read blocks\n");
            return -1;
        }

        // Copy buffer from location
        memcpy(buf, buffer + loc, (size_t)block_amount_left);

        fd.read_ptr += block_amount_left;
        read += block_amount_left;
        left -= block_amount_left;
        buf += block_amount_left;
    }

    file_descriptor[fileID] = fd;

    free(buffer);
    return read;
}
int sfs_fseek(int fileID, int loc)
{
    if (fileID <= 0 || fileID > NUM_FILES)
    { // fileID 0 is reserved for root
        printf("Error: File ID %d is invalid\n", fileID);
        return -1;
    }

    // make sure file already open
    if (file_descriptor[fileID].inode_index == -1)
    {
        printf("Error: File is not open\n");
        return -1;
    }

    if (loc < 0)
    {
        file_descriptor[fileID].write_ptr = 0;
    }
    else if (loc > iNode_table[file_descriptor[fileID].inode_index].size)
    {
        file_descriptor[fileID].write_ptr = iNode_table[file_descriptor[fileID].inode_index].size;
    }
    else
    {
        file_descriptor[fileID].write_ptr = loc;
    }

    return 0;
}

int sfs_remove(char *file)
{
    // Check if file name is valid
    if (if_name_valid(file) < 0)
    {
        return -1;
    }

    // Get index of inode in directory by iterating in directory
    int iNodeIndex = get_iNode_index_in_directory(file_list, file);

    if (iNodeIndex == -1)
    {
        printf("Error: File to be removed does not exist\n");
        return -1;
    }
    else
    {
        // Remove file from fd table and reinitialize file descriptor table entry
        for (int i = 1; i < NUM_INODES; i++)
        {
            if (file_descriptor[i].inode_index == iNodeIndex)
            {
                file_descriptor[i] = (file_descriptor_entry){-1, NULL, 0, 0};
                num_files--;
            }
        }
    }

    iNode *inode;
    inode = &iNode_table[iNodeIndex];

    int last_block_used = (*inode).size / BLOCK_SIZE;
    int addresses[(BLOCK_SIZE / sizeof(int))]; // Pointers inside indirect block
    int if_addr_Init = 0;              // 1 if addresses have been initialized
    int indirectBlockIndex;
    int indirectBlockAddressModified = 0; // Boolean, 1 if address in indirect block is modified

    buffer = (void *)malloc(BLOCK_SIZE);
    for (int i = 0; i <= last_block_used; i++)
    {
        memset(buffer, 0, BLOCK_SIZE);
        if (i > 11)
        {
            // Removing in indirect pointers
            if (!if_addr_Init)
            {
                if ((*inode).indirectPointer == -1)
                {
                    if ((*inode).size != 12 * BLOCK_SIZE)
                    {
                        printf("Error: Issue with size\n");
                        return -1;
                    }
                    break;
                }
                // Initialize addresses
                read_blocks((*inode).indirectPointer, 1, buffer);
                memcpy(addresses, buffer, BLOCK_SIZE);
                memset(buffer, 0, BLOCK_SIZE);
                if_addr_Init = 1;
            }

            indirectBlockIndex = i - 12;
            if (addresses[indirectBlockIndex] == -1)
            {
                if ((*inode).size != i * BLOCK_SIZE)
                {
                    printf("Error: Issue with size\n");
                    return -1;
                }
                break;
            }
            write_blocks(addresses[indirectBlockIndex], 1, buffer);
            bitmap_free_one_bit(addresses[indirectBlockIndex]);
            addresses[indirectBlockIndex] = -1;
            indirectBlockAddressModified = 1;
        }
        else
        {
            // Removing in direct pointers
            write_blocks((*inode).data_ptrs[i], 1, buffer);
            bitmap_free_one_bit((*inode).data_ptrs[i]);
            (*inode).data_ptrs[i] = -1;
        }
    }

    // Write indirectBlock back to disk if its address has been modified
    if (indirectBlockAddressModified)
    {
        memset(buffer, 0, BLOCK_SIZE);
        memcpy(buffer, addresses, BLOCK_SIZE);
        write_blocks((*inode).indirectPointer, 1, buffer);
        indirectBlockAddressModified = 0;
    }

    // Reset inode's indirect pointer and size
    if (if_addr_Init)
    { // indirectPointer has valid block address
        bitmap_free_one_bit((*inode).indirectPointer);
        (*inode).indirectPointer = -1;
    }
    else
    {
        if ((*inode).indirectPointer != -1)
        {
            printf("Error: Indirect pointer should be -1\n");
            return -1;
        }
    }
    (*inode).size = -1;
    free(buffer);
    // Write inode table to disk
        if (write_blocks(NUM_SUPERBLOCK_BLOCKS, NUM_INODE_BLOCKS, (void *)(&iNode_table)) < 0)
        {
            printf("Error: Failed to write iNode table to disk\n");
        }

    // Write file list to disk
        if (write_blocks(DATA_BLOCK_START-1, 1, (void *)(&free_bitmap)) < 0)
        {
            printf("Error: Failed to write free bitmap to disk\n");
        }
    
    // Write file list to disk
        if (write_blocks(DATA_BLOCK_START, NUM_FILE_LIST_BLOCKS, (void *)(&file_list)) < 0)
        {
            printf("Error: Failed to write file list to disk\n");
        }

    return 0;
}

void init_superblock()
{
    // Initialization
    sb.magic = 0xACBD0005;
    sb.block_size = BLOCK_SIZE;
    sb.fs_size = NUM_BLOCKS;
    sb.inode_table_length = NUM_INODES;
    sb.root_dir_inode_index = 0;
}

void init_file_descripter()
{
    // First entry in file descriptor is root
    file_descriptor[0].inode_ptr = &iNode_table[0];
    file_descriptor[0].inode_index = 0;
    file_descriptor[0].read_ptr = 0;
    file_descriptor[0].write_ptr = 0;

    // Initialize other entries
    for (int i = 1; i < NUM_INODES; i++)
    {
        file_descriptor[i].inode_index = -1; // To be assigned
        file_descriptor[i].inode_ptr = NULL; // To be assigned
        file_descriptor[i].read_ptr = 0;
        file_descriptor[i].write_ptr = 0;
    }
}

void init_iNode_table()
{
    // First entry in inode_table is root iNode
    iNode_table[0].size = 0;
    iNode_table[0].data_ptrs[0] = DATA_BLOCK_START;
    for (int i = 1; i < 12; i++)
    {
        iNode_table[0].data_ptrs[i] = 0;
    }
    iNode_table[0].indirectPointer = 0;

    // Initialize the other entries
    for (int i = 1; i < NUM_INODES; i++)
    {
        iNode_table[i] = (iNode){-1, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0};
    }
}

// Initialize file list of the root directory
void init_file_list()
{
    for (int i = 1; i < NUM_FILES; i++)
    {
        file_list[i].iNode_index = -1;
        file_list[i].file_name = 0; // empty string (end-of-string character)
    }
}

int if_name_valid(const char *name)
{
    // Check the length of the filename
    int i = 0;
    while (name[i] != '.')
    {
        if (i >= MAXFILENAME)
        {
            printf("Error: Invalid file name\n");
            return 0;
        }
        i++;
    }
    // Check the length of the extension
    int j = 0;
    while (name[i + j + 1] != '\0')
    {
        if (j >= MAX_EXTENSION)
        {
            printf("Error: Invalid file extension\n");
            return 0;
        }
        j++;
    }
    return 1;
}

int get_iNode_index_in_directory(directory_entry dir[], char *filename)
{
    for (int i = 0; i < NUM_FILES; i++)
    {
        if (strcmp(dir[i].file_name, filename) == 0)
        {
            return dir[i].iNode_index; // File found, return inode index
        }
    }
    return -1; // File not found, return -1
}

int bitmap_occupy_one_bit()
{
    // occupy the first section with a free bit and return it
    int i = 0;
    while (free_bitmap[i] == 1) {
        i++;
    }
    return i;
}

void bitmap_free_one_bit(int i)
{
    free_bitmap[i] = 0;
}

void set_index(int i)
{
    if (i < 0 || i > 1023) {
        printf("Error: outside the bound\n");
        return;
    }

    // use bit
    free_bitmap[i] = 0;
}