#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdint.h>
#include <stdarg.h> /* Needed for variadic macros */
#include <stdbool.h> /* Needed for bool type */

/* Macro for verbose printing */
#define DEBUG_PRINT(fmt, ...)                    \
    do {                                         \
        if (verbose)                             \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
    } while (0)

/*
 * comparePhdr:
 *   qsort comparator ordering program headers by load address (p_paddr).
 *   Sorts ascending so segments land in increasing memory order.
 */
static int comparePhdr(const void* a, const void* b)
{
    const GElf_Phdr* pa = a;
    const GElf_Phdr* pb = b;
    if (pa->p_paddr < pb->p_paddr) {
        return -1;
    }
    if (pa->p_paddr > pb->p_paddr) {
        return 1;
    }
    return 0;
}

int main(int argCount, char** argValues)
{
    int         noSht            = 0;
    int         hasRange         = 0;
    int         allowZeroSizeSeg = 0; /* New flag for zero-size segments */
    uint64_t    minLma           = 0;
    uint64_t    maxLma           = 0;
    const char* inputFile        = NULL;
    const char* outputFile       = NULL;
    int         verbose          = 0;
    int         opt;
    int         option_index = 0; /* For getopt_long */

    /* Define long options */
    static struct option long_options[] = {
        {"nosht", no_argument, 0, 'n'},       /* --nosht is equivalent to -n */
        {"range", required_argument, 0, 'r'}, /* --range is equivalent to -r */
        {"verbose", no_argument, 0, 'v'}, /* --verbose is equivalent to -v */
        {"zero-size-segments", no_argument, 0, 'z'}, /* --zero-size-segments */
        {0, 0, 0, 0}};

    /* Use getopt_long to parse command-line options */
    optind = 1; /* Reset optind */
    while ((opt = getopt_long(argCount, argValues, "nr:vz", long_options,
                              &option_index)) != -1) {
        switch (opt) {
            case 'n':
                noSht = 1;
                break;
            case 'r': {
                /* Parse the range string (e.g., "0xA00000000-0xB0000000") */
                hasRange      = 1;
                char* dashPos = strchr(optarg, '-');
                if (!dashPos) {
                    fprintf(stderr,
                            "Invalid range format. Expected: min-max\n");
                    return EXIT_FAILURE;
                }

                /* Split the string */
                *dashPos     = '\0';
                char* minStr = optarg;
                char* maxStr = dashPos + 1;

                /* Check for hex or decimal format and convert */
                if (strncmp(minStr, "0x", 2) == 0 ||
                    strncmp(minStr, "0X", 2) == 0) {
                    minLma = strtoull(minStr, NULL, 16);
                }
                else {
                    minLma = strtoull(minStr, NULL, 10);
                }

                if (strncmp(maxStr, "0x", 2) == 0 ||
                    strncmp(maxStr, "0X", 2) == 0) {
                    maxLma = strtoull(maxStr, NULL, 16);
                }
                else {
                    maxLma = strtoull(maxStr, NULL, 10);
                }

                /* Restore the dash for error messages */
                *(dashPos) = '-';

                if (minLma >= maxLma) {
                    fprintf(stderr,
                            "Invalid range: min must be less than max\n");
                    return EXIT_FAILURE;
                }
            } break;
            case 'v':
                verbose = 1;
                break;
            case 'z':
                allowZeroSizeSeg = 1;
                break;
            case '?': /* getopt_long prints an error message */
                fprintf(stderr,
                        "Usage: %s [-n | --nosht] [-r | --range min-max] "
                        "[-v | --verbose] [-z | --zero-size-segments] "
                        "<input.elf> <output.elf>\n",
                        argValues[0]);
                return EXIT_FAILURE;
            default:
                /* Should not happen */
                abort();
        }
    }

    /* Check for the correct number of positional arguments */
    if (optind + 2 != argCount) {
        fprintf(stderr,
                "Usage: %s [-n | --nosht] [-r | --range min-max] "
                "[-v | --verbose] [-z | --zero-size-segments] "
                "<input.elf> <output.elf>\n",
                argValues[0]);
        return EXIT_FAILURE;
    }

    inputFile  = argValues[optind];
    outputFile = argValues[optind + 1];

    /* Print initial configuration if verbose */
    DEBUG_PRINT("Verbose mode enabled.\n");
    DEBUG_PRINT("Input file: %s\n", inputFile);
    DEBUG_PRINT("Output file: %s\n", outputFile);
    DEBUG_PRINT("No SHT: %s\n", noSht ? "yes" : "no");
    DEBUG_PRINT("Allow zero-size segments: %s\n",
                allowZeroSizeSeg ? "yes" : "no");
    if (hasRange) {
        DEBUG_PRINT("Range filter: 0x%lx - 0x%lx\n", minLma, maxLma);
    }

    /* Initialize libelf library */
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf init failed: %s\n", elf_errmsg(-1));
        return EXIT_FAILURE;
    }
    DEBUG_PRINT("Initialized libelf library.\n");

    /* Open input ELF file for reading */
    int inputFd = open(inputFile, O_RDONLY);
    if (inputFd < 0) {
        perror("open inputFile");
        return EXIT_FAILURE;
    }
    DEBUG_PRINT("Opened input file: %s (fd: %d)\n", inputFile, inputFd);

    /* Create ELF descriptor from file descriptor */
    Elf* inputElf = elf_begin(inputFd, ELF_C_READ, NULL);
    if (!inputElf) {
        fprintf(stderr, "elf_begin(input): %s\n", elf_errmsg(-1));
        close(inputFd);
        return EXIT_FAILURE;
    }
    DEBUG_PRINT("Created ELF descriptor for input file.\n");

    /* Determine 32- vs 64-bit ELF class */
    int elfClass = gelf_getclass(inputElf);
    if (elfClass != ELFCLASS32 && elfClass != ELFCLASS64) {
        fprintf(stderr, "Unsupported ELF class: %d\n", elfClass);
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }
    DEBUG_PRINT("Detected ELF class: %s\n",
                elfClass == ELFCLASS32 ? "ELF32" : "ELF64");

    /* Read the ELF header into a generic GElf_Ehdr */
    GElf_Ehdr elfHeader;
    if (!gelf_getehdr(inputElf, &elfHeader)) {
        fprintf(stderr, "gelf_getehdr: %s\n", elf_errmsg(-1));
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }
    DEBUG_PRINT("Read input ELF header. Program header count: %u\n",
                elfHeader.e_phnum);

    /* Count how many program headers exist in the file */
    size_t phdrCount;
    if (elf_getphdrnum(inputElf, &phdrCount) != 0) {
        fprintf(stderr, "elf_getphdrnum: %s\n", elf_errmsg(-1));
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }
    DEBUG_PRINT("Confirmed program header count: %zu\n", phdrCount);

    /* Allocate array to hold all PT_LOAD entries */
    GElf_Phdr* phdrs     = malloc(phdrCount * sizeof(GElf_Phdr));
    size_t     loadCount = 0;

    /* Extract only PT_LOAD segments from the input PHT */
    for (size_t i = 0; i < phdrCount; i++) {
        GElf_Phdr ph;
        if (!gelf_getphdr(inputElf, i, &ph)) {
            continue;
        }
        if (ph.p_type == PT_LOAD) {
            /* Skip segments with zero filesz unless explicitly allowed */
            if (ph.p_filesz == 0 && !allowZeroSizeSeg) {
                DEBUG_PRINT("  Skipping segment %zu (LMA 0x%lx) - "
                            "zero filesz\n",
                            i, ph.p_paddr);
                continue;
            }

            /* Apply range filter if specified */
            if (hasRange) {
                uint64_t segmentEnd = ph.p_paddr + ph.p_memsz - 1;
                /* Skip segments that aren't fully contained within the range */
                if (ph.p_paddr < minLma || segmentEnd > maxLma) {
                    DEBUG_PRINT("  Skipping segment %zu (LMA 0x%lx - 0x%lx) - "
                                "outside range 0x%lx - 0x%lx\n",
                                i, ph.p_paddr, segmentEnd, minLma, maxLma);
                    continue;
                }
            }
            DEBUG_PRINT("  Keeping segment %zu (LMA 0x%lx, size 0x%lx/0x%lx, "
                        "offset 0x%lx, align %lu)\n",
                        i, ph.p_paddr, ph.p_filesz, ph.p_memsz, ph.p_offset,
                        ph.p_align);
            phdrs[loadCount++] = ph;
        }
        else {
            DEBUG_PRINT("  Skipping segment %zu (type %u)\n", i, ph.p_type);
        }
    }
    DEBUG_PRINT("Found %zu PT_LOAD segments matching criteria.\n", loadCount);
    if (loadCount == 0) {
        fprintf(stderr, "No PT_LOAD segments found\n");
        free(phdrs);
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }

    /* Sort the loadable segments by their LMA (p_paddr) */
    qsort(phdrs, loadCount, sizeof(GElf_Phdr), comparePhdr);
    DEBUG_PRINT("Sorted PT_LOAD segments by LMA.\n");

    /* Allocate storage for data buffers we read */
    void** data_buffers = calloc(loadCount, sizeof(void*));
    if (!data_buffers) {
        perror("calloc data_buffers");
        free(phdrs);
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }
    bool cleanup_buffers = true; /* Flag to track if buffers need cleanup */

    /* Open output file for writing the filtered ELF */
    int outputFd = open(outputFile, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (outputFd < 0) {
        perror("open outputFile");
        free(phdrs);
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }
    DEBUG_PRINT("Opened output file: %s (fd: %d)\n", outputFile, outputFd);

    /* Create ELF descriptor for the output */
    Elf* outputElf = elf_begin(outputFd, ELF_C_WRITE, NULL);
    if (!outputElf) {
        fprintf(stderr, "elf_begin(output): %s\n", elf_errmsg(-1));
        close(outputFd);
        free(phdrs);
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }
    DEBUG_PRINT("Created output ELF descriptor.\n");

    /* Create new ELF header matching input class */
    if (!gelf_newehdr(outputElf, elfClass)) {
        fprintf(stderr, "gelf_newehdr: %s\n", elf_errmsg(-1));
        /* Consider if continuing makes sense, maybe just log if verbose */
    }
    DEBUG_PRINT("Created new ELF header for output file (class %s).\n",
                elfClass == ELFCLASS32 ? "ELF32" : "ELF64");

    /* Update program header count and clear section info */
    elfHeader.e_phnum    = loadCount;
    elfHeader.e_shoff    = 0;
    elfHeader.e_shnum    = 0;
    elfHeader.e_shstrndx = SHN_UNDEF;
    if (!gelf_update_ehdr(outputElf, &elfHeader)) {
        fprintf(stderr, "gelf_update_ehdr: %s\n", elf_errmsg(-1));
    }
    DEBUG_PRINT("Updated output ELF header: phnum=%zu, shoff=0, shnum=0, "
                "shstrndx=SHN_UNDEF\n",
                loadCount);

    /* Reserve space for the new program header table */
    if (!gelf_newphdr(outputElf, loadCount)) {
        fprintf(stderr, "gelf_newphdr: %s\n", elf_errmsg(-1));
        /* Handle error */
    }
    DEBUG_PRINT("Reserved space for %zu program headers in output PHT.\n",
                loadCount);

    /* Write each sorted PT_LOAD entry into the new PHT */
    for (size_t i = 0; i < loadCount; i++) {
        if (!gelf_update_phdr(outputElf, i, &phdrs[i])) {
            fprintf(stderr, "gelf_update_phdr[%zu]: %s\n", i, elf_errmsg(-1));
        }
    }

    /* Flush header + PHT to the output file */
    if (elf_update(outputElf, ELF_C_WRITE) < 0) {
        fprintf(stderr, "elf_update header+PHT: %s\n", elf_errmsg(-1));
    }
    DEBUG_PRINT("Wrote initial ELF header and PHT to output file.\n");

    /* Read segment data and associate with output ELF using sections/data */
    DEBUG_PRINT("Associating segment data with output ELF...\n");
    for (size_t i = 0; i < loadCount; i++) {
        GElf_Phdr seg = phdrs[i]; /* Use the sorted phdr */

        /* Skip segments with zero file size */
        if (seg.p_filesz == 0) {
            DEBUG_PRINT("  Segment %zu has zero filesz, skipping data association\n", i);
            continue;
        }

        /* Allocate buffer for segment data */
        void* buffer = malloc(seg.p_filesz);
        if (!buffer) {
            perror("malloc segment buffer");
            goto cleanup_error; /* Use goto for centralized cleanup */
        }
        data_buffers[i] = buffer; /* Store buffer pointer for later free */

        /* Read segment data from input file */
        ssize_t bytes_read = pread(inputFd, buffer, seg.p_filesz, seg.p_offset);
        if (bytes_read < 0) {
            perror("pread segment data");
            goto cleanup_error;
        }
        else if ((size_t)bytes_read != seg.p_filesz) {
            fprintf(stderr,
                    "Warning: short read for segment %zu (expected %lu, got %zd)\n",
                    i, seg.p_filesz, bytes_read);
            /* Continue with potentially partial data, but adjust size?
               For simplicity, we'll error out on short reads for now. */
            fprintf(stderr, "Error: Short read encountered. Aborting.\n");
             goto cleanup_error;
       }

        /* Create a new section for this segment's data */
        Elf_Scn* scn = elf_newscn(outputElf);
        if (!scn) {
            fprintf(stderr, "elf_newscn[%zu]: %s\n", i, elf_errmsg(-1));
            goto cleanup_error;
        }

        /* Create a new data descriptor for the section */
        Elf_Data* data = elf_newdata(scn);
        if (!data) {
            fprintf(stderr, "elf_newdata[%zu]: %s\n", i, elf_errmsg(-1));
            goto cleanup_error;
        }

        /* Fill the data descriptor */
        data->d_align = seg.p_align;
        data->d_buf   = buffer; /* libelf reads from this buffer during elf_update */
        data->d_size  = seg.p_filesz; /* Use actual filesz */
        data->d_type  = ELF_T_BYTE;
        data->d_off   = 0LL; /* Offset within the section */

        /* We don't need elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY) because
           elf_newdata implicitly marks the section containing the data descriptor
           as dirty. elf_update will write it. */

        DEBUG_PRINT("  Associated data for segment %zu: size=0x%lx, align=%lu\n",
                     i, seg.p_filesz, seg.p_align);

        /* Note: We do NOT update the Phdr p_offset here. elf_update calculates
           the final offsets for both sections and segments based on layout. */
    }
    DEBUG_PRINT("Finished associating segment data.\n");

    /* Update ELF header section info based on noSht flag *before* final update */
    if (!gelf_getehdr(outputElf, &elfHeader)) { /* Get potentially updated header */
         fprintf(stderr, "gelf_getehdr(out pre-final): %s\n", elf_errmsg(-1));
         goto cleanup_error;
     }

    if (noSht) {
        DEBUG_PRINT("Configuring output ELF for no SHT.\n");
        elfHeader.e_shnum    = 0;
        elfHeader.e_shoff    = 0; /* elf_update will calculate final value if needed */
        elfHeader.e_shstrndx = SHN_UNDEF;
        if (!gelf_update_ehdr(outputElf, &elfHeader)) {
            fprintf(stderr, "gelf_update_ehdr (noSht): %s\n", elf_errmsg(-1));
             goto cleanup_error;
         }
    } else {
         DEBUG_PRINT("Adding NULL section header as final section.\n");
         Elf_Scn* nullScn = elf_newscn(outputElf); /* Add NULL section */
         if (!nullScn) {
             fprintf(stderr, "elf_newscn(NULL): %s\n", elf_errmsg(-1));
             goto cleanup_error;
         }
         /* GElf_Shdr is automatically SHT_NULL initialized by elf_newscn */
         /* elf_update will set the correct e_shnum and e_shstrndx (usually 0 for NULL string table) */
         DEBUG_PRINT("NULL section added; elf_update will finalize SHT info.\n");
     }

    /* Finalize all updates (offsets, sizes, data writing) */
    DEBUG_PRINT("Finalizing output ELF file (layout and data write)...\n");
    off_t final_size = elf_update(outputElf, ELF_C_WRITE);
    if (final_size < 0) {
        fprintf(stderr, "elf_update final: %s\n", elf_errmsg(-1));
        goto cleanup_error;
    }
    DEBUG_PRINT("Output ELF file finalized. Final size: %ld bytes\n", final_size);

cleanup_error:; /* Label for centralized cleanup */
    int exit_status = (errno != 0 || elf_errno() != 0) ? EXIT_FAILURE : EXIT_SUCCESS;

    /* Clean up handles and memory */
    DEBUG_PRINT("Cleaning up resources.\n");
    elf_end(outputElf);
    close(outputFd);
    if (cleanup_buffers && data_buffers) {
         for (size_t i = 0; i < loadCount; i++) {
             free(data_buffers[i]); /* Free stored buffer pointers */
         }
         free(data_buffers);
     }
    free(phdrs);
    elf_end(inputElf);
    close(inputFd);

    return exit_status;
}
