#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/**
 * @def MAX_SIGNATURE_LENGTH
 * @brief Maximum length (in bytes) of a virus signature.
 */
#define MAX_SIGNATURE_LENGTH 8
/**
 * @def MAX_VIRUS_NAME_LENGTH
 * @brief Maximum length (in characters) of a virus name string.
 */
#define MAX_VIRUS_NAME_LENGTH 256
/**
 * @def MAX_FILE_SYSTEM_ADRESS_SIZE
 * @brief Maximum length (in characters) of a file system path or address.
 */
#define MAX_FILE_SYSTEM_ADRESS_SIZE 256


/**
 * @brief Represents a virus signature.
 *
 * Contains a byte array for the signature, an offset where the signature should be located,
 * and the virus name.
 */
typedef struct
{
    unsigned char signature[MAX_SIGNATURE_LENGTH]; /**< Byte array representing the virus signature. */
    size_t offset; /**< Offset in the file where the signature is expected. */
    char virus_name[MAX_VIRUS_NAME_LENGTH]; /**< Name of the virus. */
} VirusSignature;

/**
 * @brief Here is a list of all enums with links to the files they belong to:
 *
 * - The error naming convention follows this pattern:
 *   The error is named by the current function (CF) + the error function (EF) = CF_VARIABLE_EF_ERROR:
 *   Example: Error with the OFFSET variable in the FSCANF function.
 *   RS - Read Signature (current function), fscanf(file, "%zx", &vs->offset) - error function.
 *   The error name will be: RS_OFFSET_FSCANF_ERROR.
 *
 * - If there is an error with the variable value, the following naming convention is used:
 *   Current function (CF) + error value (EV) + variable name (VN) = CF_EV_VN:
 *   Example: Error with the variable FILE_PATH (VN) - NULL POINTER (EV) in the current function RS (Read Signature; CF).
 *   The error will be named: RS_NULL_FILE_PATH_POINTER.
 *
 * - For special return values, I will also use an enum for simplification.
 */

/**
 * @enum Error_Codes_RS
 * @brief Error codes for the read_signature() function.
 *
 * These codes represent different failure scenarios that might occur
 * when reading a virus signature from a file.
 *
 * @note Each error code corresponds to a specific issue during file handling or
 *       signature parsing. Use these error codes to troubleshoot issues with
 *       file reading operations in the `read_signature` function.
 *
 * @see read_signature() for function utilizing these error codes.
 * @retval Error_Codes_RS See the enum for possible return values.
 */
enum Error_Codes_RS
{
    /** @brief No errors, function completed successfully. */
    RS_SUCCESS = 0,

    /** @brief File path argument is NULL. */
    RS_NULL_FILE_PATH_POINTER = 1,

    /** @brief Virus structure pointer is NULL. */
    RS_NULL_VSTRUCT_POINTER = 2,

    /** @brief Failed to open file. */
    RS_FILE_FOPEN_ERROR = 3,

    /** @brief Failed to read signature from file. */
    RS_SIGNATURE_FSCANF_ERROR = 4,

    /** @brief Failed to set file-position-indicator (offset). */
    RS_OFFSET_FSCANF_ERROR = 5,

    /** @brief Failed to read virus name from file. */
    RS_VNAME_FSCANF_ERROR = 6,

    /** @brief Failed to close file descriptor. */
    RS_FILE_FCLOSE_ERROR = 7
};

/**
 * @enum Error_Codes_EXE
 * @brief Error codes for the is_exec() function.
 *
 * These codes represent different failure scenarios that might occur
 * when checking 2 firsts bytes of file (Checking file if it's executable permission)
 *
 * @see is_exec() for function utilizing these error codes.
 * @retval Error_Codes_EXE See the enum for possible return values.
 */
enum Error_Codes_EXE
{
    /** @brief No errors, function completed successfully. */
    EXE_SUCCESS = 0,

    /** @brief File path argument is NULL. */
    EXE_NULL_FILE_PATH_POINTER = 1,

    /** @brief Execution flag pointer is NULL. */
    EXE_NULL_EFLAG_POINTER = 2,

    /** @brief Failed to open the specified file. */
    EXE_FILE_FOPEN_ERROR = 3,

    /** @brief Failed to read data from the file into the buffer. */
    EXE_BUFFER_FREAD_ERROR = 4,

    /** @brief Failed to close the file descriptor. */
    EXE_FILE_FCLOSE_ERROR = 5,
};

/**
 * @enum Error_Codes_CFS
 * @brief Error codes for the calculate_file_size() function.
 *
 * CFS - Calculate File Size.
 * These error codes help to identify various issues that can occur
 * while determining the size of a file.
 *
 * @note Each error code corresponds to a specific failure during file
 *       handling or file size calculation.
 *
 * @see calculate_file_size() for function utilizing these error codes.
 * @retval Error_Codes_CFS See the enum for possible return values.
 */
enum Error_Codes_CFS
{
    /** @brief No errors, function completed successfully. */
    CFS_SUCCESS = 0,

    /** @brief The file path argument is NULL. */
    CFS_NULL_FILE_PATH_POINTER = 1,

    /** @brief The file size pointer argument is NULL. */
    CFS_NULL_FILE_SIZE_POINTER = 2,

    /** @brief The file could not be opened. */
    CFS_FILE_FOPEN_ERROR = 3,

    /** @brief Failed to set file position to the end of the file. */
    CFS_END_FSEEK_ERROR = 4,

    /** @brief Failed to obtain the current value of the file-position indicator. */
    CFS_SIZE_FTELL_ERROR = 5,

    /** @brief The file could not be closed properly. */
    CFS_FILE_FCLOSE_ERROR = 6
};

/**
 * @enum Error_Codes_SF
 * @brief Error codes for the scan_file() function.
 *
 * SF - Scan File.
 * These error codes are used to report results and errors during
 * the process of scanning a file for virus signatures.
 *
 * @note These error codes are specifically associated with the
 * scanning process and help in identifying different types of failures
 * or issues during file scanning.
 *
 * @see scan_file() for function utilizing these error codes.
 * @retval Error_Codes_SF See the enum for possible return values.
 */
enum Error_Codes_SF
{
    /** @brief No errors, function completed successfully. */
    SF_SUCCESS = 0,

    /** @brief The file path argument is NULL. */
    SF_NULL_FILE_PATH_POINTER = 1,

    /** @brief The virus structure pointer is NULL. */
    SF_NULL_VSTRUCT_POINTER = 2,

    /** @brief The Virus Flag pointer is NULL. */
    SF_NULL_VFLAG_POINTER = 3,

    /** @brief The file could not be opened. */
    SF_FILE_FOPEN_ERROR = 4,

    /** @brief Failed to set the file position to the given offset. */
    SF_OFFSET_FSEEK_ERROR = 5,

    /** @brief Failed to read the signature from the file buffer. */
    SF_BUFFER_FREAD_ERROR = 6,

    /** @brief The file could not be closed properly during scanning. */
    SF_FILE_FCLOSE_ERROR = 7,
};

/**
 * @enum Error_Codes_Main
 * @brief Error codes for the main() function.
 *
 * MAIN - General errors related to program input/output or called subroutines.
 *
 * These error codes represent various failure cases encountered during the
 * execution of the main function, including issues with printing messages,
 * reading files, and invoking specific subroutines (e.g., read_signature and scan_file).
 *
 * @note These error codes help to diagnose and handle issues related to input/output operations,
 * file scanning, and printing results to the user.
 *
 * @see main() for the function utilizing these error codes.
 * @retval Error_Codes_Main See the enum for possible return values.
 */
enum Error_Codes_Main
{
    /** @brief No errors, function completed successfully. */
    MAIN_SUCCESS = 0,

    /** @brief Failed to print the signature file message. */
    MAIN_SIGN_PRINTF_ERROR = 1,

    /** @brief Failed to scan the signature file path. */
    MAIN_SIGN_SCANF_ERROR = 2,

    /** @brief Failed to print the target file message. */
    MAIN_TARG_PRINTF_ERROR = 3,

    /** @brief Failed to scan the target file path for possible virus. */
    MAIN_TARG_SCANF_ERROR = 4,

    /** @brief Failed to print that file is safe(NOT PE). */
    MAIN_NOT_PE_PRINTF_ERROR = 5,

    /** @brief Failed to print the error message related to is_exec(). */
    MAIN_EXEC_PRINTF_ERROR = 6,

    /** @brief An error occurred in the is_exec() function. */
    MAIN_EXEC_ERROR = 7,

    /** @brief Failed to print the error message related to read_signature(). */
    MAIN_RS_PRINTF_ERROR = 8,

    /** @brief An error occurred in the read_signature() function. */
    MAIN_RS_ERROR = 9,

    /** @brief Failed to print that file is safe(SMALL SIZE). */
    MAIN_SMALL_SIZE_PRINTF_ERROR = 10,

    /** @brief Failed to print the error message related to calculate_file_size(). */
    MAIN_CFS_PRINTF_ERROR = 11,

    /** @brief An error occurred in the calculate_file_size() function. */
    MAIN_CFS_ERROR = 12,

    /** @brief Failed to print that the file is safe(NO VIRUS). */
    MAIN_OK_PRINTF_ERROR = 13,

    /** @brief Failed to print that the file is not safe. */
    MAIN_VIRUS_PRINTF_ERROR = 14,

    /** @brief Failed to print the error message from scan_file(). */
    MAIN_SF_PRINTF_ERROR = 15,

    /** @brief An error occurred during the scan_file() function. */
    MAIN_SF_ERROR = 16
};

// Declare all functions here:
int read_signature(const char *file_path, VirusSignature *vs); // Reads a virus signature from a specified file.

int is_exec(const char *file_path, int *exe_flag); // Checks if the specified file has execution permissions.

int calculate_file_size(const char *file_path, size_t *file_size); // Calculates the size of a file specified by the file path.

int scan_file(const char *file_path, VirusSignature *vs, int *virus_flag); // Scans a file specified by the file path for virus signatures.

/**
 * @brief Entry point of the antivirus scanner.
 *
 * Prompts user for paths to the signature and target file.
 * Reports whether a virus is found based on the provided signature.
 *
 * @return Error code from @ref Error_Codes_Main.
 */
int main()
{
    // Declare all the variables:
    VirusSignature vs;
    char sign_path[MAX_FILE_SYSTEM_ADRESS_SIZE];
    char target_path[MAX_FILE_SYSTEM_ADRESS_SIZE];
    int result, exe_flag = 0, virus_flag = 0;
    const char *message;
    size_t file_size = 0;

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
        printf("Error in function:\n"
               "int printf(const char *restrict format, ...);\n"
               "Desciption: Failed to output message\n");
        return MAIN_SIGN_PRINTF_ERROR; // 1
    }

    if (scanf("%s",sign_path) != 1)
    {
        printf("Error in function:\n"
               "int scanf(const char *restrict format, ...);\n"
               "Desciption: Failed to reading signature file path\n");
        return MAIN_SIGN_SCANF_ERROR; // 2
    }

    message = "\nEnter path to target file: \n"
              "Example: target.exe OR C:\\Bin1\\Bin2\\target.exe\n";
    if (printf("%s", message) < 0)
    {
       printf("Error in function:\n"
              "int printf(const char *restrict format, ...);\n"
              "Description: Failed to output message\n");
       return MAIN_TARG_PRINTF_ERROR; // 3
    }

    if (scanf("%s",target_path) != 1)
    {
        printf("Error in function:\n"
               "int scanf(const char *restrict format, ...);\n"
               "Description: Failed to reading signature file path\n");
        return MAIN_TARG_SCANF_ERROR; // 4
    }

    // 1) MZ check (is_exec) -> 2) file size (CFS) -> 3) signatura (SF)
    result = is_exec(target_path, &exe_flag);
    if (result == 0)
    {
        if (exe_flag == 0) // flag = 1 is executable or = 0 if it's not -> file is safe
        {
            if (printf("\nAll OK, FILE(%s) is safe", target_path) < 0)
            {
                printf("Error in function:\n"
                       "int printf(const char *restrict format, ...);\n"
                       "Description: Failed to output message\n");
                return MAIN_NOT_PE_PRINTF_ERROR; // 5
            }
            return MAIN_SUCCESS; // file is safe -> program is over
        }
    }
    else // if result != EXE_SUCCESS / 0
    {
        switch(result)
        {
            case EXE_NULL_FILE_PATH_POINTER: // case 1
            {
                message = "Error in variable:\n"
                          "const char *file_path;\n"
                          "Description: Signature file path pointer is NULL\n";
                break;
            }
            case EXE_NULL_EFLAG_POINTER: // case 2
            {
                message = "Error in variable:\n"
                          "int *exe_flag;\n"
                          "Description: Exe flag pointer is NULL\n";
                break;
            }
            case EXE_FILE_FOPEN_ERROR: // case 3
            {
                message = "Error in function:\n"
                          "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                          "Description: Failed to open target file\n";
                break;
            }
            case EXE_BUFFER_FREAD_ERROR: // case 4
            {
                message = "Error in function:\n"
                          "size_t fread( void * ptrvoid, size_t size, size_t count, FILE * filestream);"
                          "Description: Failed to read bytes in target file\n";
                break;
            }
            case EXE_FILE_FCLOSE_ERROR: // case 5
            {
                message = "Error in function:\n"
                          "int fclose(FILE *stream);\n"
                          "Description: Failed to close signature file\n";
                break;
            }
            default:
            {
                message = "Error in function:\n"
                          "int is_exec(const char *file_path, int *exe_flag)\n"
                          "Description: Unknown error occurred while reading signature\n";
                break;
            }
        } // switch

        if (printf("%s", message) < 0)
        {
            printf("Error in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Desciption: Failed to output message\n");
            return MAIN_EXEC_PRINTF_ERROR; // 6
        }

        return MAIN_EXEC_ERROR; // 7
    } // if

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
            } // switch

        if (printf("%s", message) < 0)
        {
            printf("Error in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Desciption: Failed to output message\n");
            return MAIN_RS_PRINTF_ERROR; // 8
        }

        return MAIN_RS_ERROR; // 9
    } // if

    result = calculate_file_size(target_path, &file_size);
    if (result == CFS_SUCCESS) // if result == 0
    {
        //     offset + (length of signatire) > file_size -> file is safe
        if (vs.offset + (sizeof(vs.signature) / sizeof(vs.signature[0])) > file_size)
        {
            if (printf("\nAll OK, FILE(%s) is safe", target_path) < 0)
            {
                printf("Error in function:\n"
                       "int printf(const char *restrict format, ...);\n"
                       "Description: Failed to output message\n");
                return MAIN_SMALL_SIZE_PRINTF_ERROR; // 10
            }
            return MAIN_SUCCESS; // file is safe -> program is over
        }
    }
    else // if result != CFS_SUCCESS / 0
    {
        switch (result)
        {
            case CFS_NULL_FILE_PATH_POINTER: // case 1
            {
                message = "Error in variable:\n"
                          "const char *file_path;\n"
                          "Description: Target file path pointer is NULL\n";
                break;
            }
            case CFS_NULL_FILE_SIZE_POINTER: // case 2
            {
                message = "Error in variable:\n"
                          "size_t *file_size;\n"
                          "Description: File_size pointer is NULL\n";
                break;
            }
            case CFS_FILE_FOPEN_ERROR: // case 3
            {
                message = "Error in function:\n"
                          "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                          "Description: Failed to open target file\n";
                break;
            }
            case CFS_END_FSEEK_ERROR: // case 4
            {
                message = "Error in function:\n"
                          "int fseek(FILE *stream, long offset, int whence);\n"
                          "Description: Failed to set END position in file for size calculation\n";
                break;
            }
            case CFS_SIZE_FTELL_ERROR: // case 5
            {
                message = "Error in function:\n"
                          "long ftell(FILE *stream);\n"
                          "Description: Failed to tell file position for size calculation\n";
                break;
            }
            case CFS_FILE_FCLOSE_ERROR: // case 6
            {
                message = "Error in function:\n"
                          "int fclose(FILE *stream);\n"
                          "Description: Failed to close file after size calculation\n";
                break;
            }
            default:
            {
                message = "Error in function:"
                          "int calculate_file_size(const char *file_path, size_t *file_size);\n"
                          "Description: Unknown error occurred while calculating file size\n";
                break;
            }
        } // switch brackets

        if (printf("%s", message) < 0)
        {
            printf("Error in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Desciption: Failed to output message\n");
            return MAIN_CFS_PRINTF_ERROR; // 11
        }

        return MAIN_CFS_ERROR; // 12
    } // if brackets

    result = scan_file(target_path, &vs, &virus_flag);
    if (result == SF_SUCCESS) // if result == 0
    {
        if (virus_flag == 0) // virus flag = 0 -> there`s no a virus in file
        {
            if (printf("\nAll OK, FILE(%s) is safe", target_path) < 0)
            {
                printf("Error in function:\n"
                       "int printf(const char *restrict format, ...);\n"
                       "Description: Failed to output message\n");
                return MAIN_OK_PRINTF_ERROR; // 13
            }
        }
        else // virus flag = 1 -> there`s a virus in file
        {
            if (printf("\nFind VIRUS(%s) in FILE(%s)", vs.virus_name, target_path) < 0)
            {
                printf("Error in function:\n"
                       "int printf(const char *restrict format, ...);\n"
                       "Description: Failed to output message\n");
                return MAIN_VIRUS_PRINTF_ERROR; // 14
            }
        }
    }
    else // if result != 0
    {
        switch(result)
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
            case SF_NULL_VFLAG_POINTER: // case 3
            {
                message = "Error in variable:\n"
                          "int *virus_flag;\n"
                          "Description: Virus flag pointer is NULL\n";
                break;
            }
            case SF_FILE_FOPEN_ERROR: // case 4
            {
                message = "Error in function:\n"
                          "FILE *fopen(const char *restrict pathname, const char *restrict mode);\n"
                          "Description: Failed to open scan file\n";
                break;
            }
            case SF_OFFSET_FSEEK_ERROR: // case 5
            {
                message = "Error in function:\n"
                          "int fseek(FILE *stream, long offset, int whence);\n"
                          "Description: Failed to set offset position in file\n";
                break;
            }
            case SF_BUFFER_FREAD_ERROR: // case 6
            {
                message = "Error in function:\n"
                          "size_t fread(void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream);\n"
                          "Description: Failed to read buffer from file\n";
                break;
            }
            case SF_FILE_FCLOSE_ERROR: // case 7
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
            printf("Error in function:\n"
                   "int printf(const char *restrict format, ...);\n"
                   "Description: Failed to output message\n");
            return MAIN_SF_PRINTF_ERROR; // 9
        }
        return MAIN_SF_ERROR; // 10
    }

    return MAIN_SUCCESS; // 0
}

/**
 * @brief Reads a virus signature from a file.
 *
 * This function loads the virus signature, offset, and name
 * from a text file into a VirusSignature structure.
 *
 * File format should be:
 * @code
 * 4D 5A 90 00 03 00 00 00 1234 ExampleVirus
 * @endcode
 *
 * Example usage:
 * @code
 * VirusSignature vs;
 * int result = read_signature("signature.txt", &vs);
 * if (result == RS_SUCCESS)
 * {
 *     printf("Signature loaded: %s\n", vs.virus_name);
 * }
 * else
 * {
 *     printf("Error code: %d\n", result);
 * }
 * @endcode
 *
 * @param file_path Path to the file containing the signature.
 * @param vs Pointer to the VirusSignature structure to be filled.
 * @return Error code from @ref Error_Codes_RS.
 */
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

    // Declare all the variables:
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

/**
 * @brief Checks if the specified file has execution permissions.
 *
 * This function evaluates the file at the given path to determine if it is
 * executable. It sets the provided flag to indicate the result of the check.
 *
 * @param file_path The path to the file to be checked for execution permissions.
 * @param exe_flag A pointer to an integer that will be updated to 1 if the file
 *                 is executable, or 0 if it is not.
 *
 * @note This function is useful for validating file executable permission before attempting
 *       to scan a file.
 *
 * @return Error code from @ref Error_Codes_EXE.
 */
int is_exec(const char *file_path, int *exe_flag)
{
    if (file_path == NULL)
    {
        return EXE_NULL_FILE_PATH_POINTER; // 1
    }

    if (exe_flag == NULL)
    {
        return EXE_NULL_EFLAG_POINTER; // 2
    }

    // Declare all the variables:
    uint16_t MZ1 = 0, MZ2 = 0;
    FILE *file;
    int MZ_flag = 0;

    file = fopen(file_path, "rb");
    if (file == NULL)
    {
        return EXE_FILE_FOPEN_ERROR; // 3
    }

    if (fread(&MZ1, sizeof(MZ1), 1, file) != 1)
    {
        fclose(file);
        return EXE_BUFFER_FREAD_ERROR; // 4
    }

    if (fclose(file) != 0)
    {
        fclose(file);
        return EXE_FILE_FCLOSE_ERROR; // 5
    }
    MZ2 = (('Z' << 8) | 'M'); // MZ bytes in hexadecimal format
    if (MZ1 == MZ2)
    {
        MZ_flag = 1; //
    }
//    printf("%04X\n",MZ1);
//    printf("%04X\n",MZ2);
//    printf("%d\n",MZ_flag);

    *exe_flag = MZ_flag;
    return EXE_SUCCESS; // 0
}

/**
 * @brief Calculates the size of a file.
 *
 * This function determines the total number of bytes in the file specified
 * by the given path and stores the result in a provided variable.
 *
 * Example usage:
 * @code
 * size_t file_size = 0;
 * int result = calculate_file_size("target.exe", &file_size);
 * if (result == CFS_SUCCESS)
 * {
 *     printf("File size: %zu bytes\n", file_size);
 * }
 * else
 * {
 *     printf("Error calculating file size: %d\n", result);
 * }
 * @endcode
 *
 * @param file_path Path to the file.
 * @param file_size Pointer to a variable to store the resulting file size.
 * @return Error code from @ref Error_Codes_CFS.
 */
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

    // Declare all the variables:
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

/**
 * @brief Scans a file for a known virus signature.
 *
 * This function checks whether the given file is a PE (Portable Executable) file,
 * verifies that the file is large enough to contain the virus signature at the specified offset,
 * and compares the contents of the file at that offset to the known virus signature.
 *
 * Example usage:
 * @code
 * VirusSignature vs;
 * int rs_result, sf_result;
 *
 * rs_result = read_signature("signature.txt", &vs);
 * if (rs_result != RS_SUCCESS)
 * {
 *     printf("Error reading signature: %d\n", rs_result);
 * }
 *
 * int sf_result = scan_file("target.exe", &vs);
 * switch (sf_result)
 * {
 *     case SF_SUCCESS:
 *     {
 *         printf("The file is clean.\n");
 *         break;
 *     }
 *     case SF_VIRUS_DETECTED:
 *     {
 *         printf("Virus detected!\n");
 *         break;
 *     }
 *     default:
 *     {
 *         printf("Error during scan: %d\n", sf_result);
 *     }
 * @endcode
 *
 * @param file_path Path to the file to scan.
 * @param vs Pointer to a VirusSignature structure containing the known signature.
 * @return Error code from @ref Error_Codes_SF.
 */
int scan_file(const char *file_path, VirusSignature *vs, int *virus_flag)
{
    if (file_path == NULL)
    {
        return SF_NULL_FILE_PATH_POINTER; // 1
    }

    if (vs == NULL)
    {
        return SF_NULL_VSTRUCT_POINTER; // 2
    }

    if (virus_flag == NULL)
    {
        return SF_NULL_VFLAG_POINTER; // 3
    }

    // Declare all the variables:
    unsigned char buffer[MAX_SIGNATURE_LENGTH];
    size_t element_size, elements_number;
    int flag = 0; // flag for virus flag;
    FILE *file;

    file = fopen(file_path, "rb");
    if (file == NULL)
    {
        return SF_FILE_FOPEN_ERROR; // 4
    }

    if (fseek(file, vs->offset, SEEK_SET) != 0)
    {
        fclose(file);
        return SF_OFFSET_FSEEK_ERROR; // 14
    }

    element_size = sizeof(buffer[0]);
    elements_number = sizeof(buffer)/sizeof(buffer[0]);

    if (fread(buffer, element_size, elements_number, file) != elements_number)
    {
        fclose(file);
        return SF_BUFFER_FREAD_ERROR; // 15
    }
    // if equal -> memcmp should be 0 -> virus in file -> file is not safe
    if (memcmp(buffer, vs->signature, elements_number) == 0)
    {
        // if flag = 1 -> virus in file; else if flag = 0 -> virus not in file
        flag = 1; // virus in file
    }
    //else flag = 0; This could be either an error in the memcmp function itself or the fact that there is no virus
    if (fclose(file) != 0)
    {
        fclose(file);
        return SF_FILE_FCLOSE_ERROR; // 16
    }

    *virus_flag = flag;

    return SF_SUCCESS; // 0
}
