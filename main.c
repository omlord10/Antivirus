#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_SIGNATURE_LENGTH 8
#define MAX_VIRUS_NAME_LENGTH 256
#define MAX_FILE_SYSTEM_ADRESS_SIZE 256

typedef struct
{
    unsigned char signature[MAX_SIGNATURE_LENGTH];
    size_t offset;
    char virus_name[MAX_VIRUS_NAME_LENGTH];
} VirusSignature;

// Oshibka nazivayetsya: RS - read signature - func,
// VIRABLE_FUNCTION_ERROR; Example: Error with variable OFFSET in func FSCANF ->
// -> ERROR name will be RS_OFFSET_FSCANF_ERROR
enum Error_Codes_RS
{
    RS_SUCCESS, // All good
    RS_NULL_FILE_PATH_POINTER, // first arg NULL
    RS_NULL_VSTRUCT_POINTER, // VSTRUCT - Virus Structure, second arg NULL
    RS_FILE_FOPEN_ERROR, // File - Descriptor, failed to open file
    RS_SIGNATURE_FSCANF_ERROR, // Signature - array, failed to read signature in file
    RS_OFFSET_FSCANF_ERROR, // Offset - position, failed to set file-position-indicator in file
    RS_VNAME_FSCANF_ERROR, // VNAME - virus name, failed to read VNAME in file
    RS_FILE_FCLOSE_ERROR // Failed to close descriptor (file)
};

int read_signature(const char *file_path, VirusSignature *vs)
{
    if (file_path == NULL)
    {
        return RS_NULL_FILE_PATH_POINTER; // 1
    }
    if (vs == NULL)
    {
        return RS_NULL_VSTRUCT_POINTER; // 2
    }

    size_t i;
    FILE *file = fopen(file_path, "r");

    if (file == NULL)
    {
        return RS_FILE_FOPEN_ERROR; // 3
    }

    for (i = 0; i < sizeof(vs->signature) / sizeof(vs->signature[0]); i++)
    {
        if (fscanf(file, "%hhx", &vs->signature[i]) != 1)
        {
            fclose(file);
            return RS_SIGNATURE_FSCANF_ERROR; // 4
        }
    }

    if (fscanf(file, "%zx", &vs->offset) != 1)
    {
        fclose(file);
        return RS_OFFSET_FSCANF_ERROR; // 5
    }

    if (fscanf(file, "%s", vs->virus_name) != 1)
    {
        fclose(file);
        return RS_VNAME_FSCANF_ERROR; // 6
    }

    if (fclose(file) != 0)
    {
        fclose(file);
        return RS_FILE_FCLOSE_ERROR; // 7
    }
    return RS_SUCCESS; // 0
}

//CFS - Calculate File Size
enum Error_Codes_CFS
{
    CFS_SUCCESS, // All good
    CFS_NULL_FILE_PATH_POINTER, // Null 1st arg
    CFS_NULL_FILE_SIZE_POINTER, // Null 2nd arg
    CFS_FILE_FOPEN_ERROR, // File - descriptor, failed to open file
    CFS_END_FSEEK_ERROR, // Failed to set position to the end of file
    CFS_SIZE_FTELL_ERROR, // Failed to obtain the current value of the file-position indicator
    CFS_FILE_FCLOSE_ERROR // Failed to close descriptor(file)
};

int calculate_file_size(const char *file_path, size_t *file_size)
{
    if (file_path == NULL)
    {
        return CFS_NULL_FILE_PATH_POINTER; // 1
    }

    if (file_size == NULL)
    {
        return CFS_NULL_FILE_SIZE_POINTER; // 2
    }

    long size;
    FILE *file = fopen(file_path, "rb");

    if (file == NULL)
    {
        return CFS_FILE_FOPEN_ERROR; // 3
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return CFS_END_FSEEK_ERROR; // 4
    }

    size = ftell(file);

    if (size == -1)
    {
        fclose(file);
        return CFS_SIZE_FTELL_ERROR; // 5
    }

    *file_size = size;

    if (fclose(file) != 0)
    {
        fclose(file);
        return CFS_FILE_FCLOSE_ERROR; // 6
    }
    return CFS_SUCCESS; // 0
}

// SF - Scan File
enum Error_Codes_SF
{
    SF_SUCCESS, // All good
    SF_NULL_FILE_PATH_POINTER, // Null 1st argument
    SF_NULL_VSTRUCT_POINTER, // Null 2nd argument
    SF_FILE_FOPEN_ERROR, // File - descriptor, failed to open file
    SF_MZ_FREAD_ERROR, // MZ - array for reading the first 2 bytes, failed to read bytes
    SF_NOT_PE, // File is not PE -> this fill is safe
    // SF_CFS -> Function CFS error during function SF
    // CFS - Calculate File Size, SF - Scan File
    // Read enum Error_Codes_CFS to understand SF_CFS... Errors
    SF_CFS_NULL_PATH_POINTER, // Null 1st arg
    SF_CFS_NULL_FILE_SIZE_POINTER, // Null 2nd arg
    SF_CFS_FILE_FOPEN_ERROR, // File - descriptor, failed to open file
    SF_CFS_END_FSEEK_ERROR, // Failed to set position to the end of file
    SF_CFS_SIZE_FTELL_ERROR, // Failed to obtain the current value of the file-position indicator
    SF_CFS_FILE_FCLOSE_ERROR, // Failed to close descriptor(file)
    SF_SMALL_FILE_SIZE, // offset + (length of signature) > file_size -> file is safe
    SF_OFFSET_FSEEK_ERROR, // Failed to set a position on the OFFSET number
    SF_BUFFER_FREAD_ERROR, // Failed to read signature in target file
    SF_FILE_FCLOSE_ERROR, // Failed to close file
    SF_VIRUS_DETECTED // signature == buffer -> virus in file -> file is not safe
};

int scan_file(const char *file_path, VirusSignature *vs)
{
    if (file_path == NULL)
    {
        return SF_NULL_FILE_PATH_POINTER; // 1
    }

    if (vs == NULL)
    {
        return SF_NULL_VSTRUCT_POINTER; // 2
    }

    unsigned char buffer[MAX_SIGNATURE_LENGTH]; //add MZ[2] if you want another way to check MZ bytes -> uncomment code below
    size_t element_size, elements_number, file_size;
    int result, MZ_flag = 0, flag; // MZ_flag -> MZ, flag -> memcmp
    FILE *file;
    uint16_t MZ1 = 0, MZ2 = 0;

    file = fopen(file_path, "rb");
    if (file == NULL)
    {
        return SF_FILE_FOPEN_ERROR; // 3
    }
    // snachala proverka na MZ -> zatem na file_size -> zatem na signaturu
    if (fread(&MZ1, sizeof(uint16_t), 1, file) != 1)
    {
        fclose(file);
        return SF_MZ_FREAD_ERROR; // 4
    }

    MZ2 = (('Z' << 8) | 'M');
    if (MZ1 == MZ2)
    {
        MZ_flag = 1;
    }
    //printf("%04X\n",MZ1);
    //printf("%04X\n",MZ2);
    //printf("%d\n",flag);
    if (MZ_flag == 0)
    {
        fclose(file);
        return SF_NOT_PE; // 5
    }

    result = calculate_file_size(file_path, &file_size);
    if (result != CFS_SUCCESS) // case 0
    {
        switch (result)
        {
            case CFS_NULL_FILE_PATH_POINTER: // case 1
            {
                fclose(file);
                return SF_CFS_NULL_PATH_POINTER; // 6
            }
            case CFS_NULL_FILE_SIZE_POINTER: // case 2
            {
                fclose(file);
                return SF_CFS_NULL_FILE_SIZE_POINTER; // 7
            }
            case CFS_FILE_FOPEN_ERROR: // case 3
            {
                fclose(file);
                return SF_CFS_FILE_FOPEN_ERROR; // 8
            }
            case CFS_END_FSEEK_ERROR: // case 4
            {
                fclose(file);
                return SF_CFS_END_FSEEK_ERROR; // 9
            }
            case CFS_SIZE_FTELL_ERROR: // case 5
            {
                fclose(file);
                return SF_CFS_SIZE_FTELL_ERROR; // 10
            }
            case CFS_FILE_FCLOSE_ERROR: // case 6
            {
                fclose(file);
                return SF_CFS_FILE_FCLOSE_ERROR; // 11
            }
            default:
            {
                //nothing, maybe rewrite in the future...
                fclose(file);
                break;
            }
        }
    }
    // Proverka razmerov filov -> uncomment to check file sizes
    // printf("%zu\n\n", vs->offset + (sizeof(vs->signature) / sizeof(vs->signature[0])));
    // printf("%zu", file_size);

    // offset + (length of signatire) > file_size -> file is safe
    if (vs->offset + (sizeof(vs->signature) / sizeof(vs->signature[0])) > file_size)
    {
        fclose(file);
        return SF_SMALL_FILE_SIZE; // 12
    }

    if (fseek(file, vs->offset, SEEK_SET) != 0)
    {
        fclose(file);
        return SF_OFFSET_FSEEK_ERROR; // 13
    }

    element_size = sizeof(buffer[0]);
    elements_number = sizeof(buffer)/sizeof(buffer[0]);

    if (fread(buffer, element_size, elements_number, file) != elements_number)
    {
        fclose(file);
        return SF_BUFFER_FREAD_ERROR; // 14
    }


    // if equal -> memcmp should be 0 -> virus in file -> file is not safe
    if (memcmp(buffer, vs->signature, elements_number) == 0)
    {
        flag = 1;
    }
    else
    {
        flag = 0;
    }

    if (fclose(file) != 0)
    {
        fclose(file);
        return SF_FILE_FCLOSE_ERROR; // 15
    }
    // if flag = 1 -> virus in file; else if flag = 0 -> virus not in file -> SF_SUCCESS
    if (flag == 1)
    {
        return SF_VIRUS_DETECTED; // 16
    }

    return SF_SUCCESS; // 0
}

enum Error_Codes_Main
{
    MAIN_SUCCESS, // All good
    MAIN_SIGN_PRINTF_ERROR, // SIGN - SIGNature file message, where data is located, failed to print
    MAIN_SIGN_SCANF_ERROR, // SIGN - SIGNature file path, failed to scan file path
    MAIN_RS_PRINTF_ERROR, // Failed to print message about error in Read Signature (RS) function
    MAIN_RS_ERROR, // Failed in function Read_Signature - RS
    MAIN_TARG_PRINTF_ERROR, // TARG - TARGet file message, failed to print
    MAIN_TARG_SCANF_ERROR, // TARG - TARGet file path, where there may be a virus, failed to scan file path
    MAIN_OK_PRINTF_ERROR, // Failed to print that file is safe
    MAIN_VIRUS_PRINTF_ERROR, // Failed to print that file is not safe
    MAIN_SF_PRINTF_ERROR, // Failed to print that in SF was trouble
    MAIN_SF_ERROR // Failed in function Scan File - SF
};

int main() {
    VirusSignature vs;
    char sign_path[MAX_FILE_SYSTEM_ADRESS_SIZE];
    char target_path[MAX_FILE_SYSTEM_ADRESS_SIZE];
    int result;
    const char *message;

    message = "Welcome to the virus scanner program!\n\n"
              "This program scans files on your computer to check for viruses.\n"
              "Viruses have unique \"signatures\" - special sequences of numbers that the program can recognize.\n"
              "The program will search for these virus signatures in the file you select.\n"
              "If it finds a virus, it will alert you.\n"
              "If no viruses are found, the program will tell you the file is clean.\n"
              "To speed up the process, you can double-click on the file name, hold down CTRL and C, then press CTRL and V.\n\n"
              "Enter path to signature file: \n"
              "Example: signature.txt or D:\\\Bin1\\\Bin2\\\signature.txt\n";

    if (printf("%s",message) < 0)
    {
        perror("Error in function:\n"
               "int printf(const char *restrict format, ...);\n"
               "Desciption: Failed to output message\n");
        return MAIN_SIGN_PRINTF_ERROR; // 1
    }

    if (scanf("%s",sign_path) != 1)
    {
        perror("Error in function:\n"
               "int scanf(const char *restrict format, ...);\n"
               "Desciption: Failed to reading signature file path\n");
        return MAIN_SIGN_SCANF_ERROR; // 2
    }

    result = read_signature(sign_path, &vs);
    if (result != RS_SUCCESS) // result != 0
    {
        switch(result)
        {
            case RS_NULL_FILE_PATH_POINTER: // case 1
            {
                message = "Error in variable:\n"
                           "const char *file_path;\n"
                           "Description: Signature file path pointer is NULL\n";
                break;
            }
            case RS_NULL_VSTRUCT_POINTER: // case 2
                {
                    message = "Error in variable:\n"
                               "VirusSignature *vs;\n"
                               "Description: Virus structure pointer is NULL\n";
                    break;
                }
            case RS_FILE_FOPEN_ERROR: // case 3
                {
                    message = "Error in function:\n"
                               "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                               "Description: Failed to open signature file\n";
                    break;
                }
            case RS_SIGNATURE_FSCANF_ERROR: // case 4
                {
                    message = "Error in function:\n"
                               "int fscanf(FILE *restrict stream, const char *restrict format, ...);\n"
                               "Description: Failed to read signature from file\n";
                    break;
                }
            case RS_OFFSET_FSCANF_ERROR: // case 5
                {
                    message = "Error in function:\n"
                               "int fscanf(FILE *restrict stream, const char *restrict format, ...);\n"
                               "Description: Failed to read offset from file\n";
                    break;
                }
            case RS_VNAME_FSCANF_ERROR: // case 6
                {
                    message = "Error in function:\n"
                               "int fscanf(FILE *restrict stream, const char *restrict format, ...);\n"
                               "Description: Failed to read virus name from file\n";
                    break;
                }
            case RS_FILE_FCLOSE_ERROR: // case 7
                {
                    message = "Error in function:\n"
                               "int fclose(FILE *stream);\n"
                               "Description: Failed to close signature file\n";
                    break;
                }
            default:
                {
                message = "Error in function:\n"
                           "int read_signature(const char *file_path, VirusSignature *vs)\n"
                           "Description: Unknown error occurred while reading signature\n";
                break;
                }
        }

        if (printf("%s", message) < 0)
        {
            perror("Error in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Desciption: Failed to output message\n");
            return MAIN_RS_PRINTF_ERROR; // 3
        }

        return MAIN_RS_ERROR; // 4
    }

    message = "Enter path to target file: \n"
              "Example: target.exe OR C:\\\Bin1\\\Bin2\\target.exe\n";
    if (printf("%s", message) < 0)
    {
       perror("Error in function:\n"
              "int printf(const char *restrict format, ...);\n"
              "Description: Failed to output message\n");
       return MAIN_TARG_PRINTF_ERROR; // 5
    }

    if (scanf("%s",target_path) != 1)
    {
        perror("Error in function:\n"
               "int scanf(const char *restrict format, ...);\n"
               "Description: Failed to reading signature file path\n");
        return MAIN_TARG_SCANF_ERROR; // 6
    }

    result = scan_file(target_path, &vs);
    if ((result == SF_SUCCESS) || // if result == 0 ||
       (result == SF_NOT_PE) || //  result == 5 ||
       (result == SF_SMALL_FILE_SIZE)) // result == 12
    {
        if (printf("\nAll OK, FILE(%s) is safe", target_path) < 0)
        {
            perror("Error in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Description: Failed to output message\n");
            return MAIN_OK_PRINTF_ERROR; // 7
        }
    }
    else if (result == SF_VIRUS_DETECTED) // if (result == 16)
    {
        if (printf("\nFind VIRUS(%s) in FILE(%s)", vs.virus_name, target_path) < 0)
        {
            perror("Error in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Description: Failed to output message\n");
            return MAIN_VIRUS_PRINTF_ERROR; // 8
        }
    }
    else
    {
        switch(result) // There are no cases 0, 5, 12, 16 in this switch
                       // 0 = SF_SUCCESS, 5 = SF_NOT_PE, 12 = SF_SMALL_FILE_SIZE
                       // 16 = SF_VIRUS_DETECTED
        {
            case SF_NULL_FILE_PATH_POINTER: // case 1
            {
                message = "Error in variable:\n"
                          "const char *file_path;\n"
                          "Description: Scan file path pointer is NULL\n";
                break;
            }
            case SF_NULL_VSTRUCT_POINTER: // case 2
            {
                message = "Error in variable:\n"
                          "VirusSignature *vs;\n"
                          "Description: Virus structure pointer is NULL\n";
                break;
            }
            case SF_FILE_FOPEN_ERROR: // case 3
            {
                message = "Error in function:\n"
                          "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                          "Description: Failed to open scan file\n";
                break;
            }
            case SF_MZ_FREAD_ERROR: // case 4
            {
                message = "Error in function:\n"
                          "size_t fread(void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream);\n"
                          "Description: Failed to read MZ header from file\n";
                break;
            }
            case SF_CFS_NULL_PATH_POINTER: // case 6
            {
                message = "Error in variable:\n"
                          "const char *file path;"
                          "Description: In function int calculate_file_size(const char *file_path, size_t *file_size) "
                          "file path pointer is NULL\n";
                break;
            }
            case SF_CFS_NULL_FILE_SIZE_POINTER: // case 7
            {
                message = "Error in variable:\n"
                          "size_t *file_size;\n"
                          "Description: In function int calculate_file_size(const char *file_path, size_t *file_size) "
                          "file size pointer is NULL\n";
                break;
            }
            case SF_CFS_FILE_FOPEN_ERROR: // case 8
            {
                message = "Error in function:\n"
                          "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                          "Description: In function int calculate_file_size(const char *file_path, size_t *file_size) "
                          "failed to open file for size calculation\n";
                break;
            }
            case SF_CFS_END_FSEEK_ERROR: // case 9
            {
                message = "Error in function:\n"
                          "int fseek(FILE *stream, long offset, int whence);\n"
                          "Description: In function int calculate_file_size(const char *file_path, size_t *file_size) "
                          "failed to set offset position in file for size calculation\n";
                break;
            }
            case SF_CFS_SIZE_FTELL_ERROR: // case 10
            {
                message = "Error in function:\n"
                          "long ftell(FILE *stream);\n"
                          "Description: In function int calculate_file_size(const char *file_path, size_t *file_size) "
                          "failed to tell file position for size calculation\n";
                break;
            }
            case SF_CFS_FILE_FCLOSE_ERROR: // case 11
            {
                message = "Error in function:\n"
                          "int fclose(FILE *stream);\n"
                          "Description: In function int calculate_file_size(const char *file_path, size_t *file_size) "
                          "failed to close file after size calculation\n";
                break;
            }
            case SF_OFFSET_FSEEK_ERROR: // case 13
            {
                message = "Error in function:\n"
                          "int fseek(FILE *stream, long offset, int whence);\n"
                          "Description: Failed to set offset position in file\n";
                break;
            }
            case SF_BUFFER_FREAD_ERROR: // case 14
            {
                message = "Error in function:\n"
                          "size_t fread(void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream);\n"
                          "Description: Failed to read buffer from file\n";
                break;
            }
            case SF_FILE_FCLOSE_ERROR: // case 15
            {
                message = "Error in function:\n"
                          "int fclose(FILE *stream);\n"
                          "Description: Failed to close scan file\n";
                break;
            }
            default:
            {
                message = "Error in function:"
                          "int scan_file(const char *file_path, VirusSignature *vs);\n"
                          "Description: Unknown error occurred while scaninng signature\n";
                break;
            }
        }

        if (printf("%s", message) < 0)
        {
            perror("Error in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Description: Failed to output message\n");
            return MAIN_SF_PRINTF_ERROR; // 9
        }
        return MAIN_SF_ERROR; // 10
    }

    return MAIN_SUCCESS; // 0
}
