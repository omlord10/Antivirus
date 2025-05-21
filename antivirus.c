#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_SIGNATURE_LENGTH 8
#define MAX_VIRUS_NAME_LENGTH 256
#define MAX_FS_ADRESS_SIZE 256
#define STR2(x) #x
#define STR(x) STR2(x)

typedef struct
{
    unsigned char signature[MAX_SIGNATURE_LENGTH];
    size_t offset;
    char virus_name[MAX_VIRUS_NAME_LENGTH];
} VirusSignature;

enum Error_Codes_RS
{
    RS_SUCCESS = 0,
    RS_NULL_FILE_PATH_POINTER = 1,
    RS_NULL_VSTRUCT_POINTER = 2,
    RS_FILE_FOPEN_ERROR = 3,
    RS_SIGNATURE_FSCANF_ERROR = 4,
    RS_OFFSET_FSCANF_ERROR = 5,
    RS_VNAME_FSCANF_ERROR = 6,
    RS_FILE_FCLOSE_ERROR = 7
};

enum Error_Codes_EXE
{
    EXE_SUCCESS = 0,
    EXE_NULL_FILE_PATH_POINTER = 1,
    EXE_NULL_EFLAG_POINTER = 2,
    EXE_FILE_FOPEN_ERROR = 3,
    EXE_BUFFER_FREAD_ERROR = 4,
    EXE_FILE_FCLOSE_ERROR = 5,
};

enum Error_Codes_CFS
{
    CFS_SUCCESS = 0,
    CFS_NULL_FILE_PATH_POINTER = 1,
    CFS_NULL_FILE_SIZE_POINTER = 2,
    CFS_FILE_FOPEN_ERROR = 3,
    CFS_END_FSEEK_ERROR = 4,
    CFS_SIZE_FTELL_ERROR = 5,
    CFS_FILE_FCLOSE_ERROR = 6
};

enum Error_Codes_SF
{
    SF_SUCCESS = 0,
    SF_NULL_FILE_PATH_POINTER = 1,
    SF_NULL_VSTRUCT_POINTER = 2,
    SF_NULL_VFLAG_POINTER = 3,
    SF_FILE_FOPEN_ERROR = 4,
    SF_OFFSET_FSEEK_ERROR = 5,
    SF_BUFFER_FREAD_ERROR = 6,
    SF_FILE_FCLOSE_ERROR = 7,
};

enum Error_Codes_Main
{
    MAIN_SUCCESS = 0,
    MAIN_SIGN_PRINTF_ERROR = 1,
    MAIN_SIGN_SCANF_ERROR = 2,
    MAIN_TARG_PRINTF_ERROR = 3,
    MAIN_TARG_SCANF_ERROR = 4,
    MAIN_NOT_PE_PRINTF_ERROR = 5,
    MAIN_EXEC_PRINTF_ERROR = 6,
    MAIN_EXEC_ERROR = 7,
    MAIN_RS_PRINTF_ERROR = 8,
    MAIN_RS_ERROR = 9,
    MAIN_SMALL_SIZE_PRINTF_ERROR = 10,
    MAIN_CFS_PRINTF_ERROR = 11,
    MAIN_CFS_ERROR = 12,
    MAIN_OK_PRINTF_ERROR = 13,
    MAIN_VIRUS_PRINTF_ERROR = 14,
    MAIN_SF_PRINTF_ERROR = 15,
    MAIN_SF_ERROR = 16
};

int read_signature(const char *file_path, VirusSignature *vs);
int is_exec(const char *file_path, int *exe_flag);
int calculate_file_size(const char *file_path, size_t *file_size);
int scan_file(const char *file_path, VirusSignature *vs, int *virus_flag);
int main()
{
    VirusSignature vs;
    char sign_path[MAX_FS_ADRESS_SIZE];
    char target_path[MAX_FS_ADRESS_SIZE];
    int result, exe_flag = 0, virus_flag = 0;
    const char *message;
    size_t file_size = 0;
    int ch;

    message = "Welcome to the virus scanner program!\n\n"
              "This program scans files on your computer to check for viruses.\n"
              "Viruses have unique \"signatures\" - special sequences of numbers that the program can recognize.\n"
              "The program will search for these virus signatures in the file you select.\n"
              "If it finds a virus, it will alert you.\n"
              "If no viruses are found, the program will tell you the file is clean.\n"
              "Note: The program only supports file names/paths that consist\n"
              "solely of Latin alphabet letters. Any other characters will result in a file reading error.\n\n"
              "Enter path to signature file: \n"
              "Example: signature.txt or D:\\Bin1\\Bin2\\signature.txt\n";
    if (printf("%s",message) < 0)
    {
        printf("\nError in function:\n"
               "int printf(const char *restrict format, ...);\n"
               "Desciption: Failed to output message\n");
        return MAIN_SIGN_PRINTF_ERROR;
    }
    if (scanf("%" STR(MAX_FS_ADRESS_SIZE) "[^\n]", sign_path) != 1)
    {
        printf("\nError in function:\n"
               "int scanf(const char *restrict format, ...);\n"
               "Desciption: Failed to reading signature file path\n");
        return MAIN_SIGN_SCANF_ERROR;
    }
    while ((ch = getchar()) != '\n' && ch != EOF);
    message = "\nEnter path to target file: \n"
              "Example: target.exe OR C:\\Bin1\\Bin2\\target.exe\n";
    if (printf("%s", message) < 0)
    {
       printf("\nError in function:\n"
              "int printf(const char *restrict format, ...);\n"
              "Description: Failed to output message\n");
       return MAIN_TARG_PRINTF_ERROR;
    }
    if (scanf("%" STR(MAX_FS_ADRESS_SIZE) "[^\n]", target_path) != 1)
    {
        printf("\nError in function:\n"
               "int scanf(const char *restrict format, ...);\n"
               "Description: Failed to reading signature file path\n");
        return MAIN_TARG_SCANF_ERROR;
    }
    while ((ch = getchar()) != '\n' && ch != EOF);
    result = is_exec(target_path, &exe_flag);
    if (result == 0)
    {
        if (exe_flag == 0)
        {
            if (printf("\nAll OK, FILE(%s) is safe", target_path) < 0)
            {
                printf("\nError in function:\n"
                       "int printf(const char *restrict format, ...);\n"
                       "Description: Failed to output message\n");
                return MAIN_NOT_PE_PRINTF_ERROR;
            }
            return MAIN_SUCCESS;
        }
    }
    else
    {
        switch(result)
        {
            case EXE_NULL_FILE_PATH_POINTER:
            {
                message = "\nError in variable:\n"
                          "const char *file_path;\n"
                          "Description: Signature file path pointer is NULL\n";
                break;
            }
            case EXE_NULL_EFLAG_POINTER:
            {
                message = "\nError in variable:\n"
                          "int *exe_flag;\n"
                          "Description: Exe flag pointer is NULL\n";
                break;
            }
            case EXE_FILE_FOPEN_ERROR:
            {
                message = "\nError in function:\n"
                          "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                          "Description: Failed to open target file\n";
                break;
            }
            case EXE_BUFFER_FREAD_ERROR:
            {
                message = "\nError in function:\n"
                          "size_t fread( void * ptrvoid, size_t size, size_t count, FILE * filestream);"
                          "Description: Failed to read bytes in target file\n";
                break;
            }
            case EXE_FILE_FCLOSE_ERROR:
            {
                message = "\nError in function:\n"
                          "int fclose(FILE *stream);\n"
                          "Description: Failed to close signature file\n";
                break;
            }
            default:
            {
                message = "\nError in function:\n"
                          "int is_exec(const char *file_path, int *exe_flag)\n"
                          "Description: Unknown error occurred while reading signature\n";
                break;
            }
        }
        if (printf("%s", message) < 0)
        {
            printf("\nError in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Desciption: Failed to output message\n");
            return MAIN_EXEC_PRINTF_ERROR;
        }
        return MAIN_EXEC_ERROR;
    }
    result = read_signature(sign_path, &vs);
    if (result != RS_SUCCESS)
    {
        switch(result)
        {
            case RS_NULL_FILE_PATH_POINTER:
            {
                message = "\nError in variable:\n"
                          "const char *file_path;\n"
                          "Description: Signature file path pointer is NULL\n";
                break;
            }
            case RS_NULL_VSTRUCT_POINTER:
                {
                    message = "\nError in variable:\n"
                              "VirusSignature *vs;\n"
                              "Description: Virus structure pointer is NULL\n";
                    break;
                }
            case RS_FILE_FOPEN_ERROR:
                {
                    message = "\nError in function:\n"
                              "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                              "Description: Failed to open signature file\n";
                    break;
                }
            case RS_SIGNATURE_FSCANF_ERROR:
                {
                    message = "\nError in function:\n"
                              "int fscanf(FILE *restrict stream, const char *restrict format, ...);\n"
                              "Description: Failed to read signature from file\n";
                    break;
                }
            case RS_OFFSET_FSCANF_ERROR:
                {
                    message = "\nError in function:\n"
                              "int fscanf(FILE *restrict stream, const char *restrict format, ...);\n"
                              "Description: Failed to read offset from file\n";
                    break;
                }
            case RS_VNAME_FSCANF_ERROR:
                {
                    message = "\nError in function:\n"
                              "int fscanf(FILE *restrict stream, const char *restrict format, ...);\n"
                              "Description: Failed to read virus name from file\n";
                    break;
                }
            case RS_FILE_FCLOSE_ERROR:
                {
                    message = "\nError in function:\n"
                              "int fclose(FILE *stream);\n"
                              "Description: Failed to close signature file\n";
                    break;
                }
            default:
                {
                message = "\nError in function:\n"
                          "int read_signature(const char *file_path, VirusSignature *vs)\n"
                          "Description: Unknown error occurred while reading signature\n";
                break;
                }
            }
        if (printf("%s", message) < 0)
        {
            printf("\nError in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Desciption: Failed to output message\n");
            return MAIN_RS_PRINTF_ERROR;
        }
        return MAIN_RS_ERROR;
    }
    result = calculate_file_size(target_path, &file_size);
    if (result == CFS_SUCCESS)
    {
        if (vs.offset + (sizeof(vs.signature) / sizeof(vs.signature[0])) > file_size)
        {
            if (printf("\nAll OK, FILE(%s) is safe", target_path) < 0)
            {
                printf("\nError in function:\n"
                       "int printf(const char *restrict format, ...);\n"
                       "Description: Failed to output message\n");
                return MAIN_SMALL_SIZE_PRINTF_ERROR;
            }
            return MAIN_SUCCESS;
        }
    }
    else
    {
        switch (result)
        {
            case CFS_NULL_FILE_PATH_POINTER:
            {
                message = "\nError in variable:\n"
                          "const char *file_path;\n"
                          "Description: Target file path pointer is NULL\n";
                break;
            }
            case CFS_NULL_FILE_SIZE_POINTER:
            {
                message = "\nError in variable:\n"
                          "size_t *file_size;\n"
                          "Description: File_size pointer is NULL\n";
                break;
            }
            case CFS_FILE_FOPEN_ERROR:
            {
                message = "\nError in function:\n"
                          "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                          "Description: Failed to open target file\n";
                break;
            }
            case CFS_END_FSEEK_ERROR:
            {
                message = "\nError in function:\n"
                          "int fseek(FILE *stream, long offset, int whence);\n"
                          "Description: Failed to set END position in file for size calculation\n";
                break;
            }
            case CFS_SIZE_FTELL_ERROR:
            {
                message = "\nError in function:\n"
                          "long ftell(FILE *stream);\n"
                          "Description: Failed to tell file position for size calculation\n";
                break;
            }
            case CFS_FILE_FCLOSE_ERROR:
            {
                message = "\nError in function:\n"
                          "int fclose(FILE *stream);\n"
                          "Description: Failed to close file after size calculation\n";
                break;
            }
            default:
            {
                message = "\nError in function:"
                          "int calculate_file_size(const char *file_path, size_t *file_size);\n"
                          "Description: Unknown error occurred while calculating file size\n";
                break;
            }
        }
        if (printf("%s", message) < 0)
        {
            printf("\nError in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Desciption: Failed to output message\n");
            return MAIN_CFS_PRINTF_ERROR;
        }
        return MAIN_CFS_ERROR;
    }
    result = scan_file(target_path, &vs, &virus_flag);
    if (result == SF_SUCCESS)
    {
        if (virus_flag == 0)
        {
            if (printf("\nAll OK, FILE(%s) is safe", target_path) < 0)
            {
                printf("\nError in function:\n"
                       "int printf(const char *restrict format, ...);\n"
                       "Description: Failed to output message\n");
                return MAIN_OK_PRINTF_ERROR;
            }
        }
        else
        {
            if (printf("\nFind VIRUS(%s) in FILE(%s)", vs.virus_name, target_path) < 0)
            {
                printf("\nError in function:\n"
                       "int printf(const char *restrict format, ...);\n"
                       "Description: Failed to output message\n");
                return MAIN_VIRUS_PRINTF_ERROR;
            }
        }
    }
    else
    {
        switch(result)
        {
            case SF_NULL_FILE_PATH_POINTER:
            {
                message = "\nError in variable:\n"
                          "const char *file_path;\n"
                          "Description: Scan file path pointer is NULL\n";
                break;
            }
            case SF_NULL_VSTRUCT_POINTER:
            {
                message = "\nError in variable:\n"
                          "VirusSignature *vs;\n"
                          "Description: Virus structure pointer is NULL\n";
                break;
            }
            case SF_NULL_VFLAG_POINTER:
            {
                message = "\nError in variable:\n"
                          "int *virus_flag;\n"
                          "Description: Virus flag pointer is NULL\n";
                break;
            }
            case SF_FILE_FOPEN_ERROR:
            {
                message = "\nError in function:\n"
                          "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                          "Description: Failed to open scan file\n";
                break;
            }
            case SF_OFFSET_FSEEK_ERROR:
            {
                message = "\nError in function:\n"
                          "int fseek(FILE *stream, long offset, int whence);\n"
                          "Description: Failed to set offset position in file\n";
                break;
            }
            case SF_BUFFER_FREAD_ERROR:
            {
                message = "\nError in function:\n"
                          "size_t fread(void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream);\n"
                          "Description: Failed to read buffer from file\n";
                break;
            }
            case SF_FILE_FCLOSE_ERROR:
            {
                message = "\nError in function:\n"
                          "int fclose(FILE *stream);\n"
                          "Description: Failed to close scan file\n";
                break;
            }
            default:
            {
                message = "\nError in function:"
                          "int scan_file(const char *file_path, VirusSignature *vs);\n"
                          "Description: Unknown error occurred while scaninng signature\n";
                break;
            }
        }
        if (printf("%s", message) < 0)
        {
            printf("\nError in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Description: Failed to output message\n");
            return MAIN_SF_PRINTF_ERROR;
        }
        return MAIN_SF_ERROR;
    }
    return MAIN_SUCCESS;
}

int read_signature(const char *file_path, VirusSignature *vs)
{
    if (file_path == NULL)
    {
        return RS_NULL_FILE_PATH_POINTER;
    }
    if (vs == NULL)
    {
        return RS_NULL_VSTRUCT_POINTER;
    }

    size_t i;
    FILE *file = fopen(file_path, "r");

    if (file == NULL)
    {
        return RS_FILE_FOPEN_ERROR;
    }
    for (i = 0; i < sizeof(vs->signature) / sizeof(vs->signature[0]); i++)
    {
        if (fscanf(file, "%hhx", &vs->signature[i]) != 1)
        {
            fclose(file);
            return RS_SIGNATURE_FSCANF_ERROR;
        }
    }
    if (fscanf(file, "%zx", &vs->offset) != 1)
    {
        fclose(file);
        return RS_OFFSET_FSCANF_ERROR;
    }
    if (fscanf(file, "%s", vs->virus_name) != 1)
    {
        fclose(file);
        return RS_VNAME_FSCANF_ERROR;
    }
    if (fclose(file) != 0)
    {
        fclose(file);
        return RS_FILE_FCLOSE_ERROR;
    }
    return RS_SUCCESS;
}

int is_exec(const char *file_path, int *exe_flag)
{
    if (file_path == NULL)
    {
        return EXE_NULL_FILE_PATH_POINTER;
    }
    if (exe_flag == NULL)
    {
        return EXE_NULL_EFLAG_POINTER;
    }

    uint16_t MZ1 = 0, MZ2 = 0;
    FILE *file;
    int MZ_flag = 0;

    file = fopen(file_path, "rb");
    if (file == NULL)
    {
        return EXE_FILE_FOPEN_ERROR;
    }
    if (fread(&MZ1, sizeof(MZ1), 1, file) != 1)
    {
        fclose(file);
        return EXE_BUFFER_FREAD_ERROR;
    }
    if (fclose(file) != 0)
    {
        fclose(file);
        return EXE_FILE_FCLOSE_ERROR;
    }
    MZ2 = (('Z' << 8) | 'M');
    if (MZ1 == MZ2)
    {
        MZ_flag = 1;
    }
    *exe_flag = MZ_flag;
    return EXE_SUCCESS;
}

int calculate_file_size(const char *file_path, size_t *file_size)
{
    if (file_path == NULL)
    {
        return CFS_NULL_FILE_PATH_POINTER;
    }
    if (file_size == NULL)
    {
        return CFS_NULL_FILE_SIZE_POINTER;
    }

    long size;
    FILE *file = fopen(file_path, "rb");

    if (file == NULL)
    {
        return CFS_FILE_FOPEN_ERROR;
    }
    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return CFS_END_FSEEK_ERROR;
    }
    size = ftell(file);
    if (size == -1)
    {
        fclose(file);
        return CFS_SIZE_FTELL_ERROR;
    }
    *file_size = size;
    if (fclose(file) != 0)
    {
        fclose(file);
        return CFS_FILE_FCLOSE_ERROR;
    }
    return CFS_SUCCESS;
}

int scan_file(const char *file_path, VirusSignature *vs, int *virus_flag)
{
    if (file_path == NULL)
    {
        return SF_NULL_FILE_PATH_POINTER;
    }
    if (vs == NULL)
    {
        return SF_NULL_VSTRUCT_POINTER;
    }
    if (virus_flag == NULL)
    {
        return SF_NULL_VFLAG_POINTER;
    }

    unsigned char buffer[MAX_SIGNATURE_LENGTH];
    size_t element_size, elements_number;
    int flag = 0;
    FILE *file;
    file = fopen(file_path, "rb");

    if (file == NULL)
    {
        return SF_FILE_FOPEN_ERROR;
    }
    if (fseek(file, vs->offset, SEEK_SET) != 0)
    {
        fclose(file);
        return SF_OFFSET_FSEEK_ERROR;
    }
    element_size = sizeof(buffer[0]);
    elements_number = sizeof(buffer)/sizeof(buffer[0]);
    if (fread(buffer, element_size, elements_number, file) != elements_number)
    {
        fclose(file);
        return SF_BUFFER_FREAD_ERROR;
    }
    if (memcmp(buffer, vs->signature, elements_number) == 0)
    {
        flag = 1;
    }
    if (fclose(file) != 0)
    {
        fclose(file);
        return SF_FILE_FCLOSE_ERROR;
    }
    *virus_flag = flag;
    return SF_SUCCESS;
}
