//
//  img3tool.cpp
//  img3tool
//
//  Created by tihmstar on 06.07.21.
//

#include "../include/img3tool/img3tool.hpp"
#include <libgeneral/macros.h>
#include <string.h>
extern "C"{
#include "lzssdec.h"
};

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif

#ifdef HAVE_OPENSSL
#   include <openssl/aes.h>
#   include <openssl/sha.h>
#warning TODO adjust this for HAVE_COMMCRYPTO
#   include <openssl/x509.h> //not replaced by CommCrypto
#   include <openssl/evp.h> //not replaced by CommCrypto
#else
#   ifdef HAVE_COMMCRYPTO
#       include <CommonCrypto/CommonCrypto.h>
#       include <CommonCrypto/CommonDigest.h>
#       define SHA_CTX CC_SHA1_CTX
#       define SHA1_Init CC_SHA1_Init
#       define SHA1_Update CC_SHA1_Update
#       define SHA1(d, n, md) CC_SHA1(d, n, md)
#       define SHA384(d, n, md) CC_SHA384(d, n, md)
#       define SHA_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH
#       define SHA384_DIGEST_LENGTH CC_SHA384_DIGEST_LENGTH
#   endif //HAVE_COMMCRYPTO
#endif // HAVE_OPENSSL

using namespace tihmstar;
using namespace tihmstar::img3tool;

#define putStr(s,l) printf("%.*s",(int)l,s)

namespace tihmstar {
    namespace img3tool {
        tihmstar::Mem uncompressIfNeeded(const tihmstar::Mem &compressedPayload, const char **outUsedCompression = NULL, const char **outHypervisor = NULL, size_t *outHypervisorSize = NULL);
    };
};

using namespace tihmstar;

struct img3{
    uint32_t magic; //'Img3'
    uint32_t fullSize;
    uint32_t sizeNoHeader;
    uint32_t sigCheckAreaSize;
    uint32_t identifier;
};

struct img3Tag{
    uint32_t magic;
    uint32_t totalLength;
    uint32_t dataLength;
    uint8_t data[];
};

uint32_t swap32(uint32_t v){
    return    ((v & 0xff000000) >> 24)
            | ((v & 0x00ff0000) >> 8)
            | ((v & 0x0000ff00) << 8)
            | ((v & 0x000000ff) << 24);
}

static std::string img3TagMagicToComponentName(std::string tagMagic){
    if (tagMagic == "ibss"){
        return "iBSS";
    }else if (tagMagic == "ibec"){
        return "iBEC";
    }else if (tagMagic == "illb"){
        return "LLB";
    }else if (tagMagic == "krnl"){
        return "KernelCache";
    }else if (tagMagic == "rkrn"){
        return "RestoreKernelCache";
    }else if (tagMagic == "rdsk"){
        return "RestoreRamDisk";
    }else{
        reterror("unknown tagMagic '%s'",tagMagic.c_str());
    }
}

tihmstar::Mem img3tool::uncompressIfNeeded(const tihmstar::Mem &compressedPayload, const char **outUsedCompression, const char **outHypervisor, size_t *outHypervisorSize){
    const char *payload = (const char *)compressedPayload.data();
    size_t payloadSize = compressedPayload.size();
    size_t unpackedLen = 0;
    char *unpacked = NULL;
    cleanup([&]{
        safeFree(unpacked);
    });
    tihmstar::Mem retval = compressedPayload.copy();

    if (strncmp(payload, "complzss", 8) == 0) {
        printf("Compression detected, uncompressing (%s): ", "complzss");
        if((unpacked = tryLZSS(payload, payloadSize, &unpackedLen, outHypervisor, outHypervisorSize))){
            retval = {unpacked,unpackedLen}; unpacked = NULL; unpackedLen = 0;
            printf("ok\n");
            if (outHypervisor && outHypervisorSize && *outHypervisorSize) {
                printf("Detected and extracted hypervisor!\n");
            }
            if (outUsedCompression) *outUsedCompression = "complzss";
        }else{
            printf("failed!\n");
        }
    } else if (strncmp(payload, "bvx2", 4) == 0) {
        reterror("bvx2 currently not supported");
    }

    return retval;
}

#pragma mark public

const char *img3tool::version(){
    return VERSION_STRING;
}

img3 *verifyIMG3Header(const void *buf, size_t size){
    retassure(size >= sizeof(img3), "buf too small for header");
    img3 *header = (img3*)buf;
    
    retassure(header->magic == 'Img3', "Bad magic! Got %d but expected %d",header->magic, 'Img3');
    retassure(header->fullSize <= size, "header size larger than buffer");
    retassure(header->sizeNoHeader <= header->fullSize - sizeof(img3), "header->sizeNoHeader larger than header->fullSize - sizeof(img3)");
    retassure(header->sigCheckAreaSize <= header->fullSize - sizeof(img3), "header->sizeNoHeader larger than header->fullSize - sizeof(img3)");

    return header;
}

void img3tool::printIMG3(const void *buf, size_t size){
    img3 *header = verifyIMG3Header(buf, size);
    
    printf("IMG3:\n");
    {
        uint32_t v = 0;
        v = swap32(header->magic);      printf("magic        : %.4s\n",(char*)&v);
                                        printf("size (full)  : 0x%08x\n",header->fullSize);
                                        printf("size (noHDR) : 0x%08x\n",header->sizeNoHeader);
                                        printf("size (sigChk): 0x%08x\n",header->sigCheckAreaSize);
        v = swap32(header->identifier); printf("type         : %.4s\n",(char*)&v);
    }
    printf("-------------------------\n");

    bool hasKBAG = false;
    
    uint32_t bodySize = header->sizeNoHeader;
    for (img3Tag *tag = (img3Tag *)(header+1); bodySize;bodySize-=tag->totalLength,tag = (img3Tag*)&tag->data[tag->totalLength-sizeof(img3Tag)]) {
        retassure(bodySize >= sizeof(img3Tag), "bodysize smaller than sizeof(header)");
        retassure(tag->totalLength >= sizeof(img3Tag), "tag->totalLength smaller than sizeof(img3Tag)");
        retassure(tag->totalLength <= bodySize, "tag->totalLength larger than remaining bodysize");
        retassure(tag->dataLength <= tag->totalLength, "tag->dataLength larger than tag->totalLength");
        
        
        switch (tag->magic) {
            case 'BORD':
                retassure(tag->dataLength == 4, "BORD has unexpected dataLength! Expected 0x%x but got 0x%x",0x4,tag->dataLength);
                printf("BORD: 0x%x\n",*(uint32_t*)tag->data);
                break;

            case 'CERT':
                printf("CERT: fileoffset: 0x%08lx size: 0x%08x\n",((uint8_t*)tag-(uint8_t*)buf),tag->dataLength);
                break;

            case 'CHIP':
                retassure(tag->dataLength == 4, "CHIP has unexpected dataLength! Expected 0x%x but got 0x%x",0x4,tag->dataLength);
                printf("CHIP: 0x%x\n",*(uint32_t*)tag->data);
                break;

            case 'DATA':
                printf("DATA: size 0x%08x\n",tag->dataLength);
                break;

            case 'ECID':
                retassure(tag->dataLength == 8, "ECID has unexpected dataLength! Expected 0x%x but got 0x%x",0x8,tag->dataLength);
                printf("ECID: 0x%016llx\n",*(uint64_t*)tag->data);
                break;

            case 'KBAG':
                retassure(tag->dataLength == 0x38, "KBAG got bad len. Expected 0x%x but got 0x%x",0x38,tag->dataLength);
            {
                struct kb{
                    uint32_t num;
                    uint32_t keybits;
                    uint8_t iv[0x10];
                    uint8_t key[0x20];
                } *keybag = (struct kb*)tag->data;
                retassure(keybag->keybits <= sizeof(keybag->key)*8, "Bad keybits num!");
                printf("KBAG\n\tnum: %d\n\t",keybag->num);
                for (int i=0; i<sizeof(keybag->iv); i++) printf("%02x",keybag->iv[i]);
                printf("\n\t");
                for (int i=0; i<keybag->keybits/8; i++) printf("%02x",keybag->key[i]);
                printf("\n");
                hasKBAG = true;
            }
                break;
            
            case 'SEPO':
                retassure(tag->dataLength == 4, "SEPO has unexpected dataLength! Expected 0x%x but got 0x%x",0x4,tag->dataLength);
                printf("SEPO: 0x%x\n",*(uint32_t*)tag->data);
                break;

            case 'SHSH':
                printf("SHSH: fileoffset: 0x%08lx size: 0x%08x\n",((uint8_t*)tag-(uint8_t*)buf),tag->dataLength);
#ifdef XCODE
                printf("\t");
                for (int i=0; i<tag->dataLength; i++){
                    if (i && i%0x20 == 0) printf("\n\t");
                    printf("%02x",tag->data[i]);
                }
                printf("\n");
#endif
                break;
                
            case 'TYPE':
            {
                retassure(tag->dataLength == 4, "Bad len for TYPE");
                uint32_t h = swap32(*(uint32_t*)tag->data);
                printf("TYPE: %.4s\n",(char*)&h);
            }
                break;
                
            case 'VERS':
            {
                struct vers{
                    uint32_t len;
                    char str[];
                } *v = (struct vers*)tag->data;
                printf("VERS: %.*s\n",v->len,v->str);
            }
                break;

            default:
            {
                uint32_t h = swap32(tag->magic);
                printf("unknown tag magic 0x%08x (%.4s) with size 0x%08x (fileoffset: 0x%08lx)\n",tag->magic,(char*)&h,tag->dataLength, ((uint8_t*)tag-(uint8_t*)buf));
            }
                break;
        }
    }
    
#ifdef HAVE_CRYPTO
    {
        uint8_t *sigbuf = (uint8_t*)&header->sigCheckAreaSize;
        size_t sigbufSize = sizeof(img3) - offsetof(img3, sigCheckAreaSize) + header->sigCheckAreaSize;
        uint8_t shasum[SHA_DIGEST_LENGTH] = {};
        SHA1(sigbuf, (unsigned int)sigbufSize, shasum);
        printf("---------------------------------------------\n");
        printf("       Digest: ");
        for (int i=0; i<sizeof(shasum); i++) printf("%02x",shasum[i]);
        printf("\n");
        {
            uint32_t *pmem = NULL;
            cleanup([&]{
                safeFree(pmem);
            });
            pmem = (uint32_t*)malloc(sigbufSize);
            memcpy(pmem, sigbuf, sigbufSize);
            pmem[0] += 0x40;
            SHA_CTX sha = {};
            SHA1_Init(&sha);
            SHA1_Update(&sha, pmem, sigbufSize);
            {
                *(uint32_t*)&shasum[0x00] = swap32(sha.h0);
                *(uint32_t*)&shasum[0x04] = swap32(sha.h1);
                *(uint32_t*)&shasum[0x08] = swap32(sha.h2);
                *(uint32_t*)&shasum[0x0C] = swap32(sha.h3);
                *(uint32_t*)&shasum[0x10] = swap32(sha.h4);
            }
            printf("ParitalDigest: ");
            printf("40000000");
            for (int i=0; i<sizeof(header->sigCheckAreaSize); i++) printf("%02x",((uint8_t*)&header->sigCheckAreaSize)[i]);
            for (int i=0; i<sizeof(shasum); i++) printf("%02x",shasum[i]);
            printf("\n");
        }
        
    }
#endif //HAVE_CRYPTO
    
    if (!hasKBAG) {
        printf("IMG3 does not contain KBAG values\n");
    }
}


const img3Tag *getValRawPtrFromIMG3(const void *buf, size_t size, uint32_t val){
    img3 *header = verifyIMG3Header(buf, size);
    uint32_t bodySize = header->sizeNoHeader;
    for (img3Tag *tag = (img3Tag *)(header+1); bodySize; bodySize -= tag->totalLength,tag = (img3Tag*)&tag->data[tag->totalLength-sizeof(img3Tag)]) {
        retassure(bodySize >= sizeof(img3Tag), "bodysize smaller than sizeof(header)");
        retassure(tag->totalLength >= sizeof(img3Tag), "tag->totalLength smaller than sizeof(img3Tag)");
        retassure(tag->totalLength <= bodySize, "tag->totalLength larger than remaining bodysize");
        retassure(tag->dataLength <= tag->totalLength, "tag->dataLength larger than tag->totalLength");
        if (tag->magic == val) return tag;
    }
    return NULL;
}

tihmstar::Mem img3tool::getValFromIMG3(const void *buf, size_t size, uint32_t val){
    const img3Tag *tag = getValRawPtrFromIMG3(buf, size, val);
    retassure(tag, "Failed to get tag for val '%.*s'",4,&val);
    /*
        wtf??
        DATA might be encrypted, but not a multiple of 16
        I am looking at you iOS 7.1.2 iPhone3,2
     */
    uint32_t len = tag->dataLength;
    if (tag->magic == 'DATA' && len % 0x10) {
        for (;len < tag->totalLength - sizeof(img3Tag); len++) {
            if ((len % 0x10) == 0) break;
        }
    }
    return {tag->data, len};
}

tihmstar::Mem img3tool::getPayloadFromIMG3(const void *buf, size_t size, const char *decryptIv, const char *decryptKey, const char **outUsedCompression){
    tihmstar::Mem payload = getValFromIMG3(buf, size, 'DATA');

    if (decryptIv || decryptKey) {
#ifdef HAVE_CRYPTO
        payload = decryptPayload(payload, decryptIv, decryptKey);
        info("payload decrypted");
#else
        reterror("decryption keys were provided, but img4tool was compiled without crypto backend!");
#endif //HAVE_CRYPTO
    }
    auto ret = uncompressIfNeeded(payload, outUsedCompression, NULL, NULL);
    
    return ret;
}

tihmstar::Mem img3tool::getEmptyIMG3Container(uint32_t identifier){
    tihmstar::Mem ret;
    ret.resize(sizeof(img3) + 0x20);
    img3 *header = (img3*)ret.data();
    header->magic = 'Img3';
    header->identifier = identifier;
    header->sigCheckAreaSize = header->sizeNoHeader = 0x20;
    header->fullSize = sizeof(img3) + header->sizeNoHeader;

    img3Tag *tag = (img3Tag *)(header+1);
    tag->magic = 'TYPE';
    tag->dataLength = 4;
    tag->totalLength = 0x20;
    *(uint32_t*)tag->data = identifier;
    return ret;
}

tihmstar::Mem img3tool::appendPayloadToIMG3(const tihmstar::Mem &oldImg3, uint32_t identifier, const void *payload, size_t payloadSize, const char *compression){
    uint8_t *packed = NULL;
    cleanup([&]{
        safeFree(packed);
    });
    tihmstar::Mem ret;
    tihmstar::Mem tagBuf;
    
    const uint8_t *payloadBuffer = (const uint8_t *)payload;
    
    if (compression) {
        if (strcmp(compression, "complzss") == 0) {
            size_t packedSize = payloadSize;
            printf("Compression requested, compressing (%s): ", "complzss");
            packed = (uint8_t *)malloc(packedSize);
            packedSize = lzss_compress(payloadBuffer, (uint32_t)payloadSize, packed, (uint32_t)packedSize);
            retassure(packedSize <= payloadSize, "compression buffer overflow");
            printf("ok\n");
            payloadBuffer = packed;
            payloadSize = packedSize;
        }
    }
    
    tagBuf.resize(sizeof(img3Tag) + payloadSize);
    img3Tag *tag = (img3Tag *)tagBuf.data();
    tag->magic = identifier;
    tag->dataLength = (uint32_t)payloadSize;
    tag->totalLength = tag->dataLength + sizeof(img3Tag);
    memcpy(tag->data, payloadBuffer, tag->dataLength);

    ret.append(oldImg3.data(), oldImg3.size());
    ret.append(tagBuf.data(), tagBuf.size());
    
    img3 *header = (img3*)ret.data();
    header->fullSize += tag->totalLength;
    header->sizeNoHeader += tag->totalLength;
    header->sigCheckAreaSize += tag->totalLength;
    
    return ret;
}

tihmstar::Mem img3tool::appendPayloadToIMG3(const tihmstar::Mem &oldImg3, uint32_t identifier, const tihmstar::Mem &payload, const char *compression){
    return appendPayloadToIMG3(oldImg3, identifier, payload.data(), payload.size(), compression);
}

tihmstar::Mem img3tool::replaceDATAinIMG3(const tihmstar::Mem &img3, const void *payload, size_t payloadSize, const char *compression){
    uint8_t *packed = NULL;
    cleanup([&]{
        safeFree(packed);
    });
    tihmstar::Mem ret;
    tihmstar::Mem tagBuf;
    
    const uint8_t *payloadBuffer = (const uint8_t *)payload;
    
    if (compression) {
        if (strcmp(compression, "complzss") == 0) {
            size_t packedSize = payloadSize;
            printf("Compression requested, compressing (%s): ", "complzss");
            packed = (uint8_t *)malloc(packedSize);
            packedSize = lzss_compress(payloadBuffer, (uint32_t)payloadSize, packed, (uint32_t)packedSize);
            retassure(packedSize <= payloadSize, "compression buffer overflow");
            printf("ok\n");
            payloadBuffer = packed;
            payloadSize = packedSize;
        }
    }
    
    ::img3 *header = verifyIMG3Header(img3.data(),img3.size());
    uint32_t bodySize = header->sizeNoHeader;
    for (img3Tag *tag = (img3Tag *)(header+1); bodySize; tag = (img3Tag*)&tag->data[tag->totalLength-sizeof(img3Tag)]) {
        retassure(bodySize >= sizeof(img3Tag), "bodysize smaller than sizeof(header)");
        retassure(tag->totalLength >= sizeof(img3Tag), "tag->totalLength smaller than sizeof(img3Tag)");
        retassure(tag->totalLength <= bodySize, "tag->totalLength larger than remaining bodysize");
        retassure(tag->dataLength <= tag->totalLength, "tag->dataLength larger than tag->totalLength");
        if (tag->magic == 'DATA') {
            tihmstar::Mem ret;
            tihmstar::Mem tagBuf;
            
            tagBuf.resize(sizeof(img3Tag) + payloadSize);
            
            img3Tag *newTag = (img3Tag *)tagBuf.data();
            newTag->magic = 'DATA';
            newTag->dataLength = (uint32_t)payloadSize;
            newTag->totalLength = newTag->dataLength + sizeof(img3Tag);
            memcpy(newTag->data, payloadBuffer, newTag->dataLength);

            ret.resize(img3.size() + newTag->totalLength - tag->totalLength);
            
            ::img3 *newheader = (::img3*)ret.data();
            {
                size_t beforeDataSize = (uint8_t*)tag - (uint8_t*)header;
                size_t afterDataSize = header->fullSize - ((uint8_t*)tag-(uint8_t*)header) - tag->totalLength;

                
                //everything before DATA
                memcpy(((uint8_t*)newheader), header, beforeDataSize);
                
                //new DATA part
                memcpy(((uint8_t*)newheader)+beforeDataSize, newTag, newTag->totalLength);
                
                //everything after DATA
                memcpy(((uint8_t*)newheader)+beforeDataSize+newTag->totalLength, &tag->data[tag->totalLength-sizeof(img3Tag)], afterDataSize);
            }
            newheader->fullSize         += newTag->totalLength - tag->totalLength;
            newheader->sizeNoHeader     += newTag->totalLength - tag->totalLength;
            newheader->sigCheckAreaSize += newTag->totalLength - tag->totalLength;
            return ret;
        }
    }
    reterror("Failed to find magic 'DATA'");
}

tihmstar::Mem img3tool::replaceDATAinIMG3(const tihmstar::Mem &img3, const tihmstar::Mem &payload, const char *compression){
    return replaceDATAinIMG3(img3, payload.data(), payload.size(), compression);
}

tihmstar::Mem img3tool::renameIMG3(const void *buf, size_t size, const char *type){
    tihmstar::Mem ret{buf,size};
    img3 *header = verifyIMG3Header(ret.data(), ret.size());
    uint32_t bodySize = header->sizeNoHeader;
    for (img3Tag *tag = (img3Tag *)(header+1); bodySize;bodySize -=tag->totalLength, tag = (img3Tag*)&tag->data[tag->totalLength-sizeof(img3Tag)]) {
        retassure(bodySize >= sizeof(img3Tag), "bodysize smaller than sizeof(header)");
        retassure(tag->totalLength >= sizeof(img3Tag), "tag->totalLength smaller than sizeof(img3Tag)");
        retassure(tag->totalLength <= bodySize, "tag->totalLength larger than remaining bodysize");
        retassure(tag->dataLength <= tag->totalLength, "tag->dataLength larger than tag->totalLength");
        if (tag->magic == 'TYPE') {
            header->identifier = htonl(*(uint32_t*)type);
            *(uint32_t*)tag->data = htonl(*(uint32_t*)type);
            return ret;
        }
    }
    reterror("Failed to rename img3");
}

tihmstar::Mem img3tool::removeTagFromIMG3(const void *buf, size_t size, uint32_t type){
    tihmstar::Mem img3{buf,size};
    ::img3 *header = verifyIMG3Header(img3.data(),img3.size());
    uint32_t bodySize = 0;

restart:
    bodySize = header->sizeNoHeader;
    for (img3Tag *tag = (img3Tag *)(header+1); bodySize;bodySize -= tag->totalLength, tag = (img3Tag*)&tag->data[tag->totalLength-sizeof(img3Tag)]) {
        retassure(bodySize >= sizeof(img3Tag), "bodysize smaller than sizeof(header)");
        retassure(tag->totalLength >= sizeof(img3Tag), "tag->totalLength smaller than sizeof(img3Tag)");
        retassure(tag->dataLength <= tag->totalLength, "tag->dataLength larger than tag->totalLength");
        if (tag->magic == type) {
            //wtf??
            size_t realTotalLen = (bodySize >= tag->totalLength) ? tag->totalLength : bodySize;
            size_t len_after = bodySize - realTotalLen;
            memmove(tag, (uint8_t*)tag + tag->totalLength, len_after);
            
            header->fullSize         -= realTotalLen;
            header->sizeNoHeader     -= realTotalLen;
            header->sigCheckAreaSize -= realTotalLen;
            goto restart;
        }
        retassure(tag->totalLength <= bodySize, "tag->totalLength larger than remaining bodysize");
    }
    
    return img3;
}

uint32_t img3tool::getImg3ImageType(const void *buf, size_t size){
    try {
        auto type = img3tool::getValFromIMG3(buf, size, 'TYPE');
        if (type.size() == 4){
            return *(uint32_t*)type.data();
        }
    } catch (tihmstar::exception &e) {
#ifdef DEBUG
        debug("failed to get IMG3 Tag for val 'TYPE' with error:\n%s",e.dumpStr().c_str());
#endif
    }
    img3 *header = verifyIMG3Header(buf, size);
    return header->identifier;
}


bool img3tool::img3ContainsKBAG(const void *buf, size_t size){
    img3 *header = verifyIMG3Header(buf, size);
    
    uint32_t bodySize = header->sizeNoHeader;
    for (img3Tag *tag = (img3Tag *)(header+1); bodySize;bodySize-=tag->totalLength,tag = (img3Tag*)&tag->data[tag->totalLength-sizeof(img3Tag)]) {
        retassure(bodySize >= sizeof(img3Tag), "bodysize smaller than sizeof(header)");
        retassure(tag->totalLength >= sizeof(img3Tag), "tag->totalLength smaller than sizeof(img3Tag)");
        retassure(tag->totalLength <= bodySize, "tag->totalLength larger than remaining bodysize");
        retassure(tag->dataLength <= tag->totalLength, "tag->dataLength larger than tag->totalLength");
        
        switch (tag->magic) {
            case 'KBAG':
                retassure(tag->dataLength == 0x38, "KBAG got bad len. Expected 0x%x but got 0x%x",0x38,tag->dataLength);
            {
                return true;
            }
                break;

            default:
                break;
        }
    }
    return false;
}
std::string img3tool::getKBAG(const void *buf, size_t size, int kbagNum){
    img3 *header = verifyIMG3Header(buf, size);
    
    uint32_t bodySize = header->sizeNoHeader;
    for (img3Tag *tag = (img3Tag *)(header+1); bodySize;bodySize-=tag->totalLength,tag = (img3Tag*)&tag->data[tag->totalLength-sizeof(img3Tag)]) {
        retassure(bodySize >= sizeof(img3Tag), "bodysize smaller than sizeof(header)");
        retassure(tag->totalLength >= sizeof(img3Tag), "tag->totalLength smaller than sizeof(img3Tag)");
        retassure(tag->totalLength <= bodySize, "tag->totalLength larger than remaining bodysize");
        retassure(tag->dataLength <= tag->totalLength, "tag->dataLength larger than tag->totalLength");
        
        
        switch (tag->magic) {
            case 'KBAG':
                retassure(tag->dataLength == 0x38, "KBAG got bad len. Expected 0x%x but got 0x%x",0x38,tag->dataLength);
            {
                struct kb{
                    uint32_t num;
                    uint32_t unknown;
                    uint8_t iv[0x10];
                    uint8_t key[0x20];
                } *keybag = (struct kb*)tag->data;
                if (keybag->num == kbagNum) {
                    std::string retval;
                    retval.resize(0x10 + 0x20);
                    memcpy((char*)&retval.data()[0], keybag->iv, sizeof(keybag->iv));
                    memcpy((char*)&retval.data()[0x10], keybag->key, sizeof(keybag->key));
                    for (int i=0x20; i<0x30; i++) if (retval.data()[i]) return retval;
                    /*
                        Very old device only use 0x20 bytes.
                        If the 0x10 last bytes are all zero, we assume that's the case
                     */
                    retval.resize(0x20);
                    return retval;
                }
            }
                break;

            default:
                break;
        }
    }
    reterror("Failed to get KBAG with num %d",kbagNum);
}

#ifdef HAVE_PLIST
tihmstar::Mem img3tool::signIMG3WithSHSH(const void *buf, size_t size, plist_t p_shshfile){
    tihmstar::Mem img3clone{buf,size};
    std::string component;
    {
        //strip old SHSH
        img3 *header = verifyIMG3Header(img3clone.data(), img3clone.size());
        uint8_t *img3buf = (uint8_t*)header;
        size_t img3BufSize = header->fullSize;
        const img3Tag *ecid = getValRawPtrFromIMG3(img3clone.data(), img3clone.size(), 'ECID');
        const img3Tag *shsh = getValRawPtrFromIMG3(img3clone.data(), img3clone.size(), 'SHSH');
        const img3Tag *cert = getValRawPtrFromIMG3(img3clone.data(), img3clone.size(), 'CERT');
        
        uint8_t *lowest = &img3buf[img3BufSize];
        if (ecid && (uint8_t*)ecid < lowest) lowest = (uint8_t*)ecid;
        if (shsh && (uint8_t*)shsh < lowest) lowest = (uint8_t*)shsh;
        if (cert && (uint8_t*)cert < lowest) lowest = (uint8_t*)cert;
        img3BufSize = lowest - img3buf;
        
        header->fullSize = (uint32_t)img3BufSize;
        header->sizeNoHeader = header->fullSize - sizeof(img3);
        if (header->sigCheckAreaSize > header->sizeNoHeader) header->sigCheckAreaSize = header->sizeNoHeader;

        //get identifier
        std::string identifier((char*)&header->identifier,(char*)&header->identifier+4);
        identifier = std::string(identifier.rbegin(),identifier.rend());
        component = img3TagMagicToComponentName(identifier);

        img3clone.resize(img3BufSize);
    }
    
    {
        //append signature
        plist_t p_component = NULL;
        plist_t p_blob = NULL;
        const char *data = NULL;
        uint64_t dataLen = 0;
        retassure(p_component = plist_dict_get_item(p_shshfile, component.c_str()),"Failed to get component '%s' from SHSH file",component.c_str());
        retassure(p_blob = plist_dict_get_item(p_component, "Blob"), "Failed to get digest");
        retassure(data = plist_get_data_ptr(p_blob, &dataLen), "Failed to get Blob data");
        img3clone.append(data, dataLen);
        
        {
            //fixup signed area
            img3 *header = verifyIMG3Header(img3clone.data(), img3clone.size());
            header->fullSize += dataLen;
            header->sizeNoHeader += dataLen;
            
            const img3Tag *shsh = getValRawPtrFromIMG3(img3clone.data(), img3clone.size(), 'SHSH');
            header->sigCheckAreaSize = (uint32_t)(((uint8_t*)shsh) - (uint8_t*)(header+1));
        }
    }
    return img3clone;
}
#endif

bool img3tool::verifySignedIMG3File(const void *buf, size_t size){
#ifndef HAVE_CRYPTO
    reterror("Compiled without crypto");
#else
    img3 *header = verifyIMG3Header(buf, size);
    uint8_t *sigbuf = (uint8_t*)&header->sigCheckAreaSize;
    size_t sigbufSize = sizeof(img3) - offsetof(img3, sigCheckAreaSize) + header->sigCheckAreaSize;

    auto certelem = getValFromIMG3(buf, size, 'CERT');
    auto shshelem = getValFromIMG3(buf, size, 'SHSH');

    {
        uint8_t shasum[SHA_DIGEST_LENGTH] = {};
        SHA1(sigbuf, (unsigned long)sigbufSize, shasum);
        printf("Digest: ");
        for (int i=0; i<sizeof(shasum); i++) printf("%02x",shasum[i]);
        printf("\n");
    }

#   ifdef HAVE_OPENSSL
    try{
        EVP_MD_CTX *mdctx = NULL;
        cleanup([&]{
            if(mdctx) EVP_MD_CTX_destroy(mdctx);
        });
        X509 *cert[2] = {};
        EVP_PKEY *certpubkey[2] = {};
        const unsigned char* certificate = NULL;
        
        assure(mdctx = EVP_MD_CTX_create());
        certificate = (const unsigned char*)certelem.data();
        for (int i=0; i<sizeof(cert)/sizeof(*cert); i++) {
            assure(cert[i] = d2i_X509(NULL, &certificate, certelem.size()));
            assure(certpubkey[i] = X509_get_pubkey(cert[i]));
        }
        assure(EVP_DigestVerifyInit(mdctx, NULL, EVP_sha1(), NULL, certpubkey[1]) == 1);
        assure(EVP_DigestVerifyUpdate(mdctx, sigbuf, sigbufSize) == 1);
        assure(EVP_DigestVerifyFinal(mdctx, (unsigned char*)shshelem.data(), shshelem.size()) == 1);
    }catch (...){
        return false;
    }
#   else
    warning("Compiled without openssl, not verifying RSA signature");
#   endif //HAVE_OPENSSL
    return true;
#endif
}

#ifdef HAVE_PLIST
bool img3tool::verifySignedIMG3FileForSHSH(const void *buf, size_t size, plist_t p_shshfile){
    tihmstar::Mem img3clone = signIMG3WithSHSH(buf, size, p_shshfile);
    return verifySignedIMG3File(img3clone.data(), img3clone.size());
}
#endif //HAVE_PLIST


#pragma mark begin_needs_crypto
#ifdef HAVE_CRYPTO
tihmstar::Mem img3tool::decryptPayload(const tihmstar::Mem &payload, const char *decryptIv, const char *decryptKey){
    uint8_t iv[16] = {};
    uint8_t key[32] = {};
    size_t keySize = 0;
    retassure(decryptIv, "decryptPayload requires IV but none was provided!");
    retassure(decryptKey, "decryptPayload requires KEY but none was provided!");


    tihmstar::Mem decPayload = payload.copy();
    size_t decryptionSize = decPayload.size() & ~0xf;

    assure(strlen(decryptIv) == sizeof(iv)*2);
    keySize = strlen(decryptKey);
    assure(keySize <= sizeof(key)*2);
    keySize >>= 1; //divide by 2
    for (int i=0; i<sizeof(iv); i++) {
        unsigned int t;
        assure(sscanf(decryptIv+i*2,"%02x",&t) == 1);
        iv[i] = t;
    }
    for (int i=0; i<keySize; i++) {
        unsigned int t;
        assure(sscanf(decryptKey+i*2,"%02x",&t) == 1);
        key[i] = t;
    }

#ifdef HAVE_OPENSSL
    AES_KEY decKey = {};
    retassure(!AES_set_decrypt_key(key, keySize*8, &decKey), "Failed to set decryption key");
    AES_cbc_encrypt((const unsigned char*)payload.data(), (unsigned char*)decPayload.data(), decryptionSize, &decKey, iv, AES_DECRYPT);
#else
#   ifdef HAVE_COMMCRYPTO
    {
        CCCryptorStatus retval = 0;
        retassure((retval = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, key, keySize, iv, payload.data(), decryptionSize, (void*)decPayload.data(), decPayload.size(), NULL)) == kCCSuccess,
                  "Decryption failed!");
    }
#   endif //HAVE_COMMCRYPTO
#endif //HAVE_OPENSSL

    return decPayload;
}
#endif //HAVE_CRYPTO
#pragma mark end_needs_crypto
