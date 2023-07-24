//
//  main.cpp
//  img3tool
//
//  Created by tihmstar on 06.07.21.
//

#include <libgeneral/macros.h>
#include "../include/img3tool/img3tool.hpp"

#include <iostream>
#include <getopt.h>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#if HAVE_PLIST
#include <plist/plist.h>
#endif //HAVE_PLIST

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif

using namespace tihmstar::img3tool;

#define FLAG_ALL        (1 << 0)
#define FLAG_EXTRACT    (1 << 1)
#define FLAG_CREATE     (1 << 2)
#define FLAG_RENAME     (1 << 3)
#define FLAG_VERIFY     (1 << 4)


static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "create",         required_argument,  NULL, 'c' },
    { "extract",        no_argument,        NULL, 'e' },
    { "rename-payload", required_argument,  NULL, 'n' },
    { "outfile",        required_argument,  NULL, 'o' },
    { "payload",        required_argument,  NULL, 'p' },
    { "replace",        required_argument,  NULL, 'r' },
#ifdef HAVE_PLIST
    { "shsh",           required_argument,  NULL, 's' },
#endif //HAVE_PLIST
    { "type",           required_argument,  NULL, 't' },
    { "verify",         no_argument,        NULL, 'v' },
    { "iv",             required_argument,  NULL,  0  },
    { "key",            required_argument,  NULL,  0  },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: img3tool [OPTIONS] FILE\n");
    printf("Parses img3 files\n\n");
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -c, --create\t<PATH>\t\tcreates img3 with raw file (last argument)\n");
    printf("  -e, --extract\t\t\textracts payload\n");
    printf("  -n, --rename-payload NAME\trename img3 payload (NAME must be exactly 4 bytes)\n");
    printf("  -o, --outfile\t\t\toutput path for extracting payload\n");
    printf("  -p, --payload\t\t\tinput img3 path for creating signed img3\n");
    printf("  -r, --replace\t<PATH>\t\treplace DATA in img3 (much like xpwntool's template feature)\n");
#ifndef HAVE_PLIST
    printf("UNAVAILABLE: ");
#endif //HAVE_PLIST
    printf("  -s, --shsh\t<PATH>\t\tFilepath for shsh\n");
    printf("  -t, --type\t\t\tset type for creating IMG3 files from raw\n");
    printf("  -v, --verify\tverify img3\n");
    printf("      --iv\t\t\tIV  for decrypting payload when extracting (requires -e and -o)\n");
    printf("      --key\t\t\tKey for decrypting payload when extracting (requires -e and -o)\n");
    printf("\n");
}

std::vector<uint8_t> readFromFile(const char *filePath){
    int fd = -1;
    cleanup([&]{
        safeClose(fd);
    });
    struct stat st{};
    std::vector<uint8_t> ret;
    
    retassure((fd = open(filePath, O_RDONLY))>0, "Failed to open '%s'",filePath);
    retassure(!fstat(fd, &st), "Failed to stat file");
    ret.resize(st.st_size);
    retassure(read(fd, ret.data(), ret.size()) == ret.size(), "Failed to read file");
    return ret;
}

#ifdef HAVE_PLIST
plist_t readPlistFromFile(const char *filePath){
    int fd = -1;
    char *buf = NULL;
    cleanup([&]{
        safeFree(buf);
        safeClose(fd);
    });
    size_t bufSize = 0;
    struct stat st = {};
    retassure((fd = open(filePath, O_RDONLY)) != -1, "Failed to open '%s'",filePath);
    retassure(!fstat(fd, &st), "Failed to stat file");
    retassure(buf = (char*)malloc(bufSize = st.st_size), "Failed to malloc buf");
    retassure(read(fd, buf, bufSize) == bufSize, "Failed to read file");
    plist_t plist = NULL;
    plist_from_memory(buf, (uint32_t)bufSize, &plist, NULL);
    return plist;
}
#endif //HAVE_PLIST


void saveToFile(const char *filePath, std::vector<uint8_t>data){
    int fd = -1;
    cleanup([&]{
        safeClose(fd);
    });
    retassure((fd = open(filePath, O_WRONLY | O_CREAT | O_TRUNC, 0644))>0, "failed to create file '%s'",filePath);
    retassure(write(fd, data.data(), data.size()) == data.size(), "failed to write to file");
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    info("%s",version());

    const char *lastArg = NULL;
    const char *outFile = NULL;
    const char *img3Type = NULL;
    const char *replaceTemplateFilePath = NULL;
    const char *decryptIv = NULL;
    const char *decryptKey = NULL;
    const char *shshFile = NULL;
    const char *payloadimg3 = NULL;

    int optindex = 0;
    int opt = 0;
    long flags = 0;

    while ((opt = getopt_long(argc, (char* const *)argv, "hc:en:o:p:r:s:t:v", longopts, &optindex)) >= 0) {
        switch (opt) {
            case 0: //long opts
            {
                std::string curopt = longopts[optindex].name;
                
                if (curopt == "iv") {
                    decryptIv = optarg;
                }else if (curopt == "key") {
                    decryptKey = optarg;
                }
                break;
            }
            case 'h':
                cmd_help();
                return 0;
            case 'e':
                retassure(!(flags & FLAG_CREATE) && !replaceTemplateFilePath, "Invalid command line arguments. can't extract and create at the same time");
                flags |= FLAG_EXTRACT;
                break;
            case 'c':
                flags |= FLAG_CREATE;
                retassure(!(flags & FLAG_EXTRACT) && !replaceTemplateFilePath, "Invalid command line arguments. can't extract and create at the same time");
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
            case 'o':
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
            case 'p':
                payloadimg3 = optarg;
                break;
            case 't':
                retassure(!img3Type, "Invalid command line arguments. img3Type already set!");
                img3Type = optarg;
                break;
            case 'r':
                retassure(!(flags & (FLAG_CREATE | FLAG_EXTRACT)), "Invalid command line arguments. can't replace, extract and create at the same time");
                replaceTemplateFilePath = optarg;
                break;
#ifdef HAVE_PLIST
            case 's':
                shshFile = optarg;
                break;
#endif //HAVE_PLIST
            case 'n': //rename-payload
                retassure(!img3Type, "Invalid command line arguments. im4pType already set!");
                img3Type = optarg;
                flags |= FLAG_RENAME;
            case 'v':
                flags |= FLAG_VERIFY;
                break;

            default:
                cmd_help();
                return -1;
        }
    }

    if (argc-optind == 1) {
        argc -= optind;
        argv += optind;
        lastArg = argv[0];
    }else{
        if (!(flags & FLAG_CREATE)) {
            cmd_help();
            return -2;
        }
    }
    
    std::vector<uint8_t> workingBuf;

    if (lastArg) {
        workingBuf = readFromFile(lastArg);
    }

    if (flags & FLAG_EXTRACT) {
        retassure(outFile, "Outfile required for operation");
        const char *compression = NULL;
        auto outdata = getPayloadFromIMG3(workingBuf.data(),workingBuf.size(), decryptIv, decryptKey);
        saveToFile(outFile, outdata);
        if (compression) {
            info("Extracted (and uncompressed %s) IMG3 payload to %s",compression,outFile);
        }else{
            info("Extracted IMG3 payload to %s",outFile);
        }
    }else if (flags & FLAG_CREATE) {
        retassure(outFile, "Outfile required for operation");
        retassure(img3Type, "img3Type required for operation");
        std::vector<uint8_t> img3;
        if (payloadimg3) {
            img3 = readFromFile(payloadimg3);
        }else{
            img3 = getEmptyIMG3Container(htonl(*(uint32_t*)img3Type));
            img3 = appendPayloadToIMG3(img3, 'DATA', workingBuf);
        }
        if (shshFile) {
#ifdef HAVE_PLIST
            plist_t p_shsh = readPlistFromFile(shshFile);
            cleanup([&]{
                safeFreeCustom(p_shsh, plist_free);
            });
            img3 = signIMG3WithSHSH(img3.data(), img3.size(), p_shsh);
#else
            error("Compiled without PLIST. Can't make signed img3");
            return -1;
#endif
        }

        saveToFile(outFile, img3);
        info("Created IMG3 file at %s",outFile);
    }else if (flags & FLAG_RENAME){
        retassure(outFile, "outputfile required");

        auto img3 = renameIMG3(workingBuf.data(), workingBuf.size(), img3Type);
        saveToFile(outFile, img3);
        info("Saved new renamed IMG3 to %s",outFile);
    } else if (replaceTemplateFilePath) {
        retassure(outFile, "Outfile required for operation");
        std::vector<uint8_t> templateFile = readFromFile(replaceTemplateFilePath);
        auto img3 = replaceDATAinIMG3(templateFile, workingBuf);
        img3 = removeTagFromIMG3(img3.data(), img3.size(), 'KBAG');
        saveToFile(outFile, img3);
        info("Created IMG3 file at %s",outFile);
    }else if (flags & FLAG_VERIFY){
        info("Verifying IMG3 file");
        bool isSigned = false;
        if (shshFile) {
#ifdef HAVE_PLIST
            plist_t p_shsh = readPlistFromFile(shshFile);
            cleanup([&]{
                safeFreeCustom(p_shsh, plist_free);
            });
            isSigned = verifySignedIMG3FileForSHSH(workingBuf.data(), workingBuf.size(), p_shsh);
#endif
            info("IMG3 file signature is %s for SHSH",isSigned ? "VALID" : "NOT valid");
        }else{
            isSigned = verifySignedIMG3File(workingBuf.data(), workingBuf.size());
            info("IMG3 file signature is %s",isSigned ? "VALID" : "NOT valid");
        }
        return isSigned ? 0 : 1;
    }else{
        //print
        printIMG3(workingBuf.data(), workingBuf.size());
    }
    
    
    return 0;
}
