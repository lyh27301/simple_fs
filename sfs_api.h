void mksfs(int fresh); // Creates the file system
int sfs_getnextfilename(char *fname); // Get the name of the next file in directory
int sfs_getfilesize(const char* path); // Get the size of the next file in directory
int sfs_fopen(char *name); // Opens the given file
int sfs_fclose(int fileID); // Closes the given file
int sfs_frseek(int fileID, int loc); // Seek (read) to the location from beginning 
int sfs_fwseek(int fileID, int loc); // Seek (write) to the location from beginning
int sfs_fwrite(int fileID, char *buf, int length); // Write buf characters into disk
int sfs_fread(int fileID, char *buf, int length); // Read characters from disk into buf
int sfs_remove(char *file);// Removes a file from the filesystem