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

/*
 * alignTo:
 *   Round 'offset' up to the next multiple of 'align'.
 *   Ensures each segment is placed on its required alignment boundary.
 */
static off_t alignTo(off_t offset, size_t align)
{
    if (align > 1)
        return (offset + align - 1) & ~(off_t)(align - 1);
    return offset;
}

/*
 * comparePhdr:
 *   qsort comparator ordering program headers by load address (p_paddr).
 *   Sorts ascending so segments land in increasing memory order.
 */
static int comparePhdr(const void* a, const void* b)
{
    const GElf_Phdr* pa = a;
    const GElf_Phdr* pb = b;
    if (pa->p_paddr < pb->p_paddr)
        return -1;
    if (pa->p_paddr > pb->p_paddr)
        return 1;
    return 0;
}

int main(int argCount, char** argValues)
{
    int         noSht = 0;
    const char* inputFile;
    const char* outputFile;

    /* Parse command-line args: optional --nosht flag */
    if (argCount == 3) {
        inputFile  = argValues[1];
        outputFile = argValues[2];
    }
    else if (argCount == 4 && strcmp(argValues[1], "--nosht") == 0) {
        noSht      = 1;
        inputFile  = argValues[2];
        outputFile = argValues[3];
    }
    else {
        fprintf(stderr, "Usage: %s [--nosht] <input.elf> <output.elf>\n",
                argValues[0]);
        return EXIT_FAILURE;
    }

    /* Initialize libelf library */
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf init failed: %s\n", elf_errmsg(-1));
        return EXIT_FAILURE;
    }

    /* Open input ELF file for reading */
    int inputFd = open(inputFile, O_RDONLY);
    if (inputFd < 0) {
        perror("open inputFile");
        return EXIT_FAILURE;
    }

    /* Create ELF descriptor from file descriptor */
    Elf* inputElf = elf_begin(inputFd, ELF_C_READ, NULL);
    if (!inputElf) {
        fprintf(stderr, "elf_begin(input): %s\n", elf_errmsg(-1));
        close(inputFd);
        return EXIT_FAILURE;
    }

    /* Determine 32- vs 64-bit ELF class */
    int elfClass = gelf_getclass(inputElf);
    if (elfClass != ELFCLASS32 && elfClass != ELFCLASS64) {
        fprintf(stderr, "Unsupported ELF class: %d\n", elfClass);
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }

    /* Read the ELF header into a generic GElf_Ehdr */
    GElf_Ehdr elfHeader;
    if (!gelf_getehdr(inputElf, &elfHeader)) {
        fprintf(stderr, "gelf_getehdr: %s\n", elf_errmsg(-1));
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }

    /* Count how many program headers exist in the file */
    size_t phdrCount;
    if (elf_getphdrnum(inputElf, &phdrCount) != 0) {
        fprintf(stderr, "elf_getphdrnum: %s\n", elf_errmsg(-1));
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }

    /* Allocate array to hold all PT_LOAD entries */
    GElf_Phdr* phdrs     = malloc(phdrCount * sizeof(GElf_Phdr));
    size_t     loadCount = 0;

    /* Extract only PT_LOAD segments from the input PHT */
    for (size_t i = 0; i < phdrCount; i++) {
        GElf_Phdr ph;
        if (!gelf_getphdr(inputElf, i, &ph))
            continue;
        if (ph.p_type == PT_LOAD) {
            phdrs[loadCount++] = ph;
        }
    }
    if (loadCount == 0) {
        fprintf(stderr, "No PT_LOAD segments found\n");
        free(phdrs);
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }

    /* Sort the loadable segments by their LMA (p_paddr) */
    qsort(phdrs, loadCount, sizeof(GElf_Phdr), comparePhdr);

    /* Open output file for writing the filtered ELF */
    int outputFd = open(outputFile, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (outputFd < 0) {
        perror("open outputFile");
        free(phdrs);
        elf_end(inputElf);
        close(inputFd);
        return EXIT_FAILURE;
    }

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

    /* Create new ELF header matching input class */
    if (!gelf_newehdr(outputElf, elfClass))
        fprintf(stderr, "gelf_newehdr: %s\n", elf_errmsg(-1));

    /* Update program header count and clear section info */
    elfHeader.e_phnum    = loadCount;
    elfHeader.e_shoff    = 0;
    elfHeader.e_shnum    = 0;
    elfHeader.e_shstrndx = SHN_UNDEF;
    if (!gelf_update_ehdr(outputElf, &elfHeader))
        fprintf(stderr, "gelf_update_ehdr: %s\n", elf_errmsg(-1));

    /* Reserve space for the new program header table */
    if (!gelf_newphdr(outputElf, loadCount))
        fprintf(stderr, "gelf_newphdr: %s\n", elf_errmsg(-1));

    /* Write each sorted PT_LOAD entry into the new PHT */
    for (size_t i = 0; i < loadCount; i++) {
        if (!gelf_update_phdr(outputElf, i, &phdrs[i]))
            fprintf(stderr, "gelf_update_phdr[%zu]: %s\n", i, elf_errmsg(-1));
    }

    /* Flush header + PHT to the output file */
    if (elf_update(outputElf, ELF_C_WRITE) < 0)
        fprintf(stderr, "elf_update header+PHT: %s\n", elf_errmsg(-1));

    /* Copy segment data in sorted order */
    off_t currentOffset = lseek(outputFd, 0, SEEK_END);
    for (size_t i = 0; i < loadCount; i++) {
        GElf_Phdr seg           = phdrs[i];
        off_t     alignedOffset = alignTo(currentOffset, seg.p_align);
        seg.p_offset            = alignedOffset;
        if (!gelf_update_phdr(outputElf, i, &seg))
            fprintf(stderr, "update_phdr offset[%zu]: %s\n", i, elf_errmsg(-1));
        void* buffer = malloc(seg.p_filesz);
        pread(inputFd, buffer, seg.p_filesz, phdrs[i].p_offset);
        pwrite(outputFd, buffer, seg.p_filesz, alignedOffset);
        free(buffer);
        currentOffset = alignedOffset + seg.p_filesz;
    }

    /* Optionally add one NULL section and point header at it */
    if (!noSht) {
        Elf_Scn* nullScn = elf_newscn(outputElf);
        if (!nullScn) {
            fprintf(stderr, "elf_newscn(NULL): %s\n", elf_errmsg(-1));
        }
        else {
            GElf_Shdr nullShdr = {0}; /* SHT_NULL */
            if (!gelf_update_shdr(nullScn, &nullShdr))
                fprintf(stderr, "gelf_update_shdr(NULL): %s\n", elf_errmsg(-1));
            GElf_Ehdr outEhdr;
            if (!gelf_getehdr(outputElf, &outEhdr))
                fprintf(stderr, "gelf_getehdr(out): %s\n", elf_errmsg(-1));
            outEhdr.e_shnum    = 1;
            outEhdr.e_shstrndx = SHN_UNDEF;
            if (!gelf_update_ehdr(outputElf, &outEhdr))
                fprintf(stderr, "gelf_update_ehdr(sections): %s\n",
                        elf_errmsg(-1));
        }
    }

    /* Finalize all updates (offsets, sizes) */
    if (elf_update(outputElf, ELF_C_WRITE) < 0)
        fprintf(stderr, "elf_update final: %s\n", elf_errmsg(-1));

    /* Clean up handles and memory */
    elf_end(outputElf);
    close(outputFd);
    free(phdrs);
    elf_end(inputElf);
    close(inputFd);

    return EXIT_SUCCESS;
}
