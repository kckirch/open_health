// Read only Oura model-key entries on a user's jailbroken device. No app attachment.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3 || !strstr(argv[1], ".com.ouraring.oura") || argv[2][0] != '/') {
        fprintf(stderr, "Usage: ipad-model-keys <Oura access group> <absolute output directory>\n");
        return 2;
    }
    if (mkdir(argv[2], 0700) != 0 && errno != EEXIST) { perror("mkdir"); return 2; }
    CFStringRef group = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrAccessGroup, group);
    CFDictionarySetValue(q, kSecAttrSynchronizable, kSecAttrSynchronizableAny);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(q, &result);
    printf("Oura metadata query status: %d\n", (int)status);
    int saved = 0;
    if (status == errSecSuccess && result && CFGetTypeID(result) == CFArrayGetTypeID()) {
        CFArrayRef items = (CFArrayRef)result;
        printf("Oura records: %ld\n", (long)CFArrayGetCount(items));
        for (CFIndex i = 0; i < CFArrayGetCount(items); i++) {
            CFDictionaryRef item = CFArrayGetValueAtIndex(items, i);
            CFTypeRef account = CFDictionaryGetValue(item, kSecAttrAccount);
            char name[512];
            if (!account || CFGetTypeID(account) != CFStringGetTypeID()
                || !CFStringGetCString(account, name, sizeof(name), kCFStringEncodingUTF8)
                || strncmp(name, "model_repository_encryption_key_", 32) != 0) continue;
            CFMutableDictionaryRef one = CFDictionaryCreateMutableCopy(NULL, 0, q);
            CFDictionaryRemoveValue(one, kSecReturnAttributes);
            CFDictionarySetValue(one, kSecMatchLimit, kSecMatchLimitOne);
            CFDictionarySetValue(one, kSecAttrAccount, account);
            CFTypeRef service = CFDictionaryGetValue(item, kSecAttrService);
            if (service) CFDictionarySetValue(one, kSecAttrService, service);
            CFDictionarySetValue(one, kSecReturnData, kCFBooleanTrue);
            CFTypeRef data = NULL;
            status = SecItemCopyMatching(one, &data);
            if (status == errSecSuccess && data && CFGetTypeID(data) == CFDataGetTypeID()) {
                CFIndex size = CFDataGetLength(data);
                char path[1024];
                int n = snprintf(path, sizeof(path), "%s/model-key-%d.bin", argv[2], saved);
                if (size > 0 && size <= 4096 && n > 0 && (size_t)n < sizeof(path)) {
                    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
                    if (fd >= 0) {
                        const UInt8 *bytes = CFDataGetBytePtr(data);
                        CFIndex written = 0;
                        while (written < size) {
                            ssize_t count = write(fd, bytes + written, (size_t)(size - written));
                            if (count <= 0) break;
                            written += count;
                        }
                        close(fd);
                        if (written == size) { saved++; printf("Saved model-key entry (%ld bytes); value hidden\n", (long)size); }
                        else { unlink(path); fprintf(stderr, "Incomplete key-file write\n"); }
                    } else perror("open");
                }
            } else printf("Model-key read status: %d\n", (int)status);
            if (data) CFRelease(data);
            CFRelease(one);
        }
    }
    if (result) CFRelease(result);
    CFRelease(q); CFRelease(group);
    printf("Model entries saved: %d\n", saved);
    return saved ? 0 : 1;
}
