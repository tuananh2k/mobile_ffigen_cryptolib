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

FFI_PLUGIN_EXPORT const char* print_file_info(char *source_file, char *destination_file){
                                char *result = malloc(256 * sizeof(char));
                                FILE *source, *destination;
                                char ch;

                                // Mở file nguồn để đọc
                                source = fopen(source_file, "rb");

                                if (source == NULL) {
                                    sprintf(result, "Không thể mở file nguồn %s.\n", source_file);
                                    return result;
                                }

                                // Mở file đích để ghi
                                destination = fopen(destination_file, "wb");

                                if (destination == NULL) {
                                    sprintf(result, "Không thể mở file đích %s.\n", destination_file);
                                    fclose(source);
                                    return result;
                                }

                                // Sao chép file nguồn sang file đích
                                while (!feof(source)) {
                                    ch = fgetc(source);
                                    if (!feof(source)) fputc(ch, destination);
                                }

                                printf("Đã sao chép thành công file từ %s sang %s.\n", source_file, destination_file);

                                // Đóng file
                                fclose(source);
                                fclose(destination);

                                sprintf(result, "Result -> path file output: %s\n", destination_file);
                                return result;
                        }