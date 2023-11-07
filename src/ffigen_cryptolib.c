#include "ffigen_cryptolib.h"
#include "error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FFI_PLUGIN_EXPORT intptr_t sum(intptr_t a, intptr_t b) { return a + b; }

FFI_PLUGIN_EXPORT intptr_t sum_long_running(intptr_t a, intptr_t b) {
#if _WIN32
  Sleep(5000);
#else
  usleep(5000 * 1000);
#endif
  return a + b;
}

FFI_PLUGIN_EXPORT const char* return_string(const char* str) {
                      return str;
                  }

FFI_PLUGIN_EXPORT const char* print_file_info(char *filename){
                            FILE *file;
                            char *result = malloc(256 * sizeof(char));
                            // Attempt to open the file
                            file = fopen(filename, "r");
                            if(file == NULL){
                                sprintf(result, "Could not open file %s",filename);
                                return result;
                            }

                            int ch;
                            int lines = 0;
                            int characters = 0;

                            while((ch = fgetc(file)) != EOF ) {
                                characters++;
                                if(ch == '\n')
                                    lines++;
                            }

                            fclose(file);

                            sprintf(result, "The file %s contains %d lines and %d characters.", filename, lines, characters);
                            return result;
                        }