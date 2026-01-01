#include <iostream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cassert>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <termios.h>
#include <sys/stat.h>
#include <memory>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <unistd.h>
#include <json/json.h>  
namespace fs = std::filesystem;

#include <openssl/sha.h>  
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>


/*
Checklist: 
 - TPM2.0 support,tools ?
 - root encrypted, found?
 - PCR prediction testing
*/

std::vector<int> pcr_list = {0,2,4,5,7,9,15};
#define DATA_DIR "/var/lib/luksury"
#define ROOT_KEY_FILE DATA_DIR "/root_keyfile.bin"
#define DRACUT_PATH "/usr/lib/dracut/modules.d/89luksury"

struct PERSISTENT_HANDLE {
    char text[16];
    TPM2_HANDLE handle;
} ;
PERSISTENT_HANDLE persistent_handle;
ESYS_CONTEXT *g_esys_ctx = nullptr;
std::vector<std::string> errors;
std::string root_device_name;
std::string root_device_uuid;
std::string root_partition_name;
TPML_PCR_SELECTION pcrSelection;
int verbosity = 1;


const char *root_key_file = ROOT_KEY_FILE;
const char *dracut_path = DRACUT_PATH;
const char *data_dir = DATA_DIR;

#define ZERO(x) memset(&x,0, sizeof(x))
int update_pcrs();
bool remove_luksury();

void adderror(const std::string& msg)
{
    std::cout << "Error: " << msg << std::endl; 
    errors.push_back(msg);
}

#include <cstdio>
#include <stdexcept>
#include <cstring>

class Tempfile {
private:
    std::string filepath;
    bool file_created;

// Common file creation logic
    void create_file(const char* data, size_t size) {
        char template_path[] = "/tmp/tempfile_XXXXXX";
        int fd = mkstemp(template_path);
        
        if (fd == -1) {
            throw std::runtime_error("Failed to create temporary file: " + std::string(strerror(errno)));
        }
        
        filepath = template_path;
        file_created = true;
        
        // Write data to the file
        std::ofstream file(filepath, std::ios::binary);
        if (!file) {
            close(fd);
            throw std::runtime_error("Failed to open temporary file for writing: " + filepath);
        }
        
        file.write(data, size);
        file.close();
        close(fd);
        
        if (!file) {
            throw std::runtime_error("Failed to write data to temporary file: " + filepath);
        }
    }

public:
    // Constructor with std::vector<unsigned char>
    Tempfile(const std::vector<unsigned char>& data) : file_created(false) {
        create_file(reinterpret_cast<const char*>(data.data()), data.size());
    }

    // Constructor with std::string
    Tempfile(const std::string& data) : file_created(false) {
        create_file(data.data(), data.size());
    }
    // Get the file path
    const std::string& get_path() const {
        return filepath;
    }

    // Check if file was successfully created
    bool is_created() const {
        return file_created;
    }

    // Read the file content (optional utility method)
    std::vector<unsigned char> read_content() const {
        if (!file_created) {
            throw std::runtime_error("Temporary file was not created");
        }
        
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("Failed to open temporary file for reading: " + filepath);
        }
        
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> buffer(size);
        file.read(reinterpret_cast<char*>(buffer.data()), size);
        
        return buffer;
    }

    // Destructor - deletes the file
    ~Tempfile() {
        if (file_created) {
            std::remove(filepath.c_str());
        }
    }

    // Delete copy constructor and assignment operator to prevent accidental copies
    Tempfile(const Tempfile&) = delete;
    Tempfile& operator=(const Tempfile&) = delete;

    // Allow move semantics
    Tempfile(Tempfile&& other) noexcept 
        : filepath(std::move(other.filepath)), file_created(other.file_created) {
        other.file_created = false;
    }
    
    Tempfile& operator=(Tempfile&& other) noexcept {
        if (this != &other) {
            // Clean up current file
            if (file_created) {
                std::remove(filepath.c_str());
            }
            
            filepath = std::move(other.filepath);
            file_created = other.file_created;
            other.file_created = false;
        }
        return *this;
    }
};

std::vector<unsigned char> loadFile(std::string path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        adderror(std::string("can't read file " + path ));
        return {};
    }

    // Get file size
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read file content
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        adderror(std::string("can't read file " + path ));
        return {};
    }
    file.close();
    return buffer;
}

bool saveFile(const std::string& path,
              const std::string& content,
              mode_t mode = 0, bool showerrors=true)       // optional octal permissions, 0 = skip
{
    std::ofstream file(path);
    if (!file.is_open()) {
        if (showerrors) adderror("can't write to file " + path);
        return false;
    }

    file << content;
    file.close();

    // If mode is non-zero, apply it
    if (mode != 0) {
        if (chmod(path.c_str(), mode) != 0) {
            adderror("chmod failed for " + path + ": " + std::string(strerror(errno)));
            return false;
        }
    }

    return true;
}
ESYS_CONTEXT *tss_esys_context() {
    ESYS_CONTEXT *ctx = nullptr;
    TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error initializing TSS context: " << Tss2_RC_Decode(rc) << std::endl;
        return nullptr;
    }
    return ctx;
}

bool tss_check_error(TSS2_RC rc, const char *msg) {
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << msg << ": " << rc << std::endl;
        return false;
    }
    return true;
}
std::vector<TPM2_HANDLE> get_tpm_persistent_handles()
{
    std::vector<TPM2_HANDLE> persistent_handles;
    TPM2_HANDLE next_handle = TPM2_PERSISTENT_FIRST;
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capability_data = nullptr;

    do {
        TSS2_RC rc;
        rc = Esys_GetCapability(
            g_esys_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM2_CAP_HANDLES,
            next_handle,
            TPM2_MAX_CAP_HANDLES,
            &more_data,
            &capability_data
        );

        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Esys_GetCapability failed: 0x" << std::hex << rc << std::endl;
            return {};
        }

        if (capability_data->capability == TPM2_CAP_HANDLES) {
            for (UINT32 i = 0; i < capability_data->data.handles.count; ++i) {
                TPM2_HANDLE handle = capability_data->data.handles.handle[i];
                persistent_handles.push_back(handle);
                next_handle = handle + 1;
            }
        }

        Esys_Free(capability_data);
        capability_data = nullptr;
    } while (more_data == TPM2_YES);

    return persistent_handles;
}

TPM2_HANDLE find_free_handle()
{
    std::vector<TPM2_HANDLE> handles = get_tpm_persistent_handles();
    TPM2_HANDLE free_handle = TPM2_PERSISTENT_FIRST + 0x700;

    while (std::find(handles.begin(), handles.end(), free_handle) != handles.end()) {
        free_handle++;
        if (free_handle >= TPM2_PERSISTENT_LAST)
        {
            return 0;
        }
    }
    return free_handle;
}

// Simple RC check helper
static int check_rc(TSS2_RC rc, const char *what) {
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << what << " failed: 0x" << std::hex << rc << std::dec << "\n";
        errors.push_back(what);
        return 1;
    }
    return 0;
}



// Helper to create a primary storage key (RSA) under the owner hierarchy.
// Returns handle in *outPrimaryHandle (ESYS_TR) which must be flushed later.
static ESYS_TR create_storage_primary(ESYS_CONTEXT *esys) {
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    inSensitive.size = sizeof(TPM2B_SENSITIVE_CREATE);
    inSensitive.sensitive.userAuth.size = 0; // empty owner auth for simplicity
    inSensitive.sensitive.data.size = 0;

    TPM2B_PUBLIC inPublic = {};
    inPublic.size = sizeof(TPM2B_PUBLIC);
    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes = (TPMA_OBJECT) (
        TPMA_OBJECT_RESTRICTED  |
        TPMA_OBJECT_DECRYPT     |
        TPMA_OBJECT_FIXEDTPM    |
        TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN
    );
    inPublic.publicArea.authPolicy.size = 0;
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.publicArea.unique.rsa.size = 0;

    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {};
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    TPM2B_PUBLIC *outPublic = nullptr;
    TSS2_RC rc = Esys_CreatePrimary(
        esys,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &inSensitive,
        &inPublic,
        &outsideInfo,
        &creationPCR,
        &primaryHandle,
        &outPublic,
        nullptr, nullptr, nullptr
    );
    if (check_rc(rc, "Esys_CreatePrimary")) return -1;

    if (outPublic) {
        Esys_Free(outPublic);
    }
    return primaryHandle;
}

TPM2B_DIGEST concatenated_to_digest(const std::vector<uint8_t>& pcrConcatenated)
{
    TPM2B_DIGEST digest;
    std::memset(&digest, 0, sizeof(digest));

    // Compute SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (pcrConcatenated.empty()) {
        // SHA256 of empty input is well-defined; we still compute it
        SHA256(nullptr, 0, hash);
    } else {
        SHA256(pcrConcatenated.data(), pcrConcatenated.size(), hash);
    }

    // Ensure the TPM2B buffer is large enough
    if (SHA256_DIGEST_LENGTH > sizeof(digest.buffer)) {
        throw std::runtime_error("TPM2B_DIGEST buffer too small for SHA256");
    }

    digest.size = (UINT16)SHA256_DIGEST_LENGTH;
    std::memcpy(digest.buffer, hash, digest.size);

    return digest;
}

bool evict_persistent( TPM2_HANDLE persistent_handle) {
    ESYS_CONTEXT* esys = g_esys_ctx;
    TSS2_RC rc;

    // Prepare a session: usually password session with TPM2_RH_OWNER
    ESYS_TR session = ESYS_TR_NONE;

    // Auth: owner hierarchy has to authorize the eviction
    rc = Esys_TR_SetAuth(esys, ESYS_TR_RH_OWNER, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    // Before you can evict, you must get an ESYS_TR for the persistent handle
    ESYS_TR persistent_tr = ESYS_TR_NONE;
    rc = Esys_TR_FromTPMPublic(
        esys,
        persistent_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &persistent_tr
    );
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    ESYS_TR out_tr = ESYS_TR_NONE;

    rc = Esys_EvictControl(
        esys,
        ESYS_TR_RH_OWNER,     // authorizing hierarchy
        persistent_tr,        // object to evict
        ESYS_TR_PASSWORD,     // auth session
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        persistent_handle,    // persistent handle to remove
        &out_tr
    );

    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    // Clean up
//    Esys_TR_Close(esys, &persistent_tr);
    return true;
}


bool seal_secret_to_persistent(
    uint32_t persistentHandle,
    const std::vector<uint8_t>& password,
    const TPML_PCR_SELECTION &pcrSelection,
    const std::vector<uint8_t>& pcrConcatenated)
    {
    
    if (pcrConcatenated.empty()) return false;
    auto digest = concatenated_to_digest(pcrConcatenated);
    
    // Create PCR policy
    ESYS_TR policySessionPCR=0;
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL
    };
   
    TSS2_RC rc;
    rc = Esys_StartAuthSession(g_esys_ctx,
                                ESYS_TR_NONE, ESYS_TR_NONE,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                NULL,
                                TPM2_SE_TRIAL,
                                &symmetric,
                                TPM2_ALG_SHA256,
                                &policySessionPCR);
    
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to start auth session: " << Tss2_RC_Decode(rc) << std::endl;
        return false;
    }
    
    // Apply PCR policy
    rc = Esys_PolicyPCR(g_esys_ctx,
                        policySessionPCR,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &digest,
                        &pcrSelection);
    
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to set PCR policy: " << Tss2_RC_Decode(rc) << std::endl;
        Esys_FlushContext(g_esys_ctx, policySessionPCR);
        return false;
    }
    
    // Get policy digest
    TPM2B_DIGEST *policyDigestPCR = nullptr;
    rc = Esys_PolicyGetDigest(g_esys_ctx,
                                policySessionPCR,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                &policyDigestPCR);
    
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to get policy digest: "  << Tss2_RC_Decode(rc) << std::endl;
        Esys_FlushContext(g_esys_ctx, policySessionPCR);
        return false;
    }


    // Prepare sensitive data (password)
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    inSensitive.sensitive.data.size = std::min(password.size(), sizeof(inSensitive.sensitive.data.buffer));
    memcpy(inSensitive.sensitive.data.buffer,  password.data(), inSensitive.sensitive.data.size);
    
    // Prepare public template
    TPM2B_PUBLIC inPublic = {};
    inPublic.size = 0;
    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes = (TPMA_OBJECT_FIXEDTPM |
                                            TPMA_OBJECT_FIXEDPARENT);
    inPublic.publicArea.authPolicy = *policyDigestPCR;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.unique.keyedHash.size = 0;
    
    // Create sealed object under Storage Root Key (SRK)
    // First, we need to get or create the SRK
    ESYS_TR srkHandle;
    
    // Try to create a primary key (SRK) in the owner hierarchy
    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = 0,
            },
            .data = {
                .size = 0,
            }
        }
    };
    
    TPM2B_PUBLIC inPublicPrimary = {};
    inPublicPrimary.size = 0;
    inPublicPrimary.publicArea.type = TPM2_ALG_RSA;
    inPublicPrimary.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublicPrimary.publicArea.objectAttributes = (TPMA_OBJECT_RESTRICTED |
                                                    TPMA_OBJECT_DECRYPT |
                                                    TPMA_OBJECT_FIXEDTPM |
                                                    TPMA_OBJECT_FIXEDPARENT |
                                                    TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                                    TPMA_OBJECT_USERWITHAUTH);
    inPublicPrimary.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    inPublicPrimary.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublicPrimary.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    inPublicPrimary.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublicPrimary.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublicPrimary.publicArea.unique.rsa.size = 0;
    
    TPM2B_DATA outsideInfoPrimary = {.size = 0};
    TPML_PCR_SELECTION creationPCRPrimary = {.count = 0};
    
    TPM2B_PUBLIC *outPublicPrimary = nullptr;
    TPM2B_CREATION_DATA *creationDataPrimary = nullptr;
    TPM2B_DIGEST *creationHashPrimary = nullptr;
    TPMT_TK_CREATION *creationTicketPrimary = nullptr;
    
    rc = Esys_CreatePrimary(g_esys_ctx,
                            ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &inSensitivePrimary,
                            &inPublicPrimary,
                            &outsideInfoPrimary,
                            &creationPCRPrimary,
                            &srkHandle,
                            &outPublicPrimary,
                            &creationDataPrimary,
                            &creationHashPrimary,
                            &creationTicketPrimary);
    
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to create primary key: " 
                    << Tss2_RC_Decode(rc) << std::endl;
        Esys_FlushContext(g_esys_ctx, policySessionPCR);
        Esys_Free(policyDigestPCR);
        return false;
    }
    
    Esys_Free(outPublicPrimary);
    Esys_Free(creationDataPrimary);
    Esys_Free(creationHashPrimary);
    Esys_Free(creationTicketPrimary);
    TPM2B_DATA outsideInfo = {.size = 0};
    TPML_PCR_SELECTION creationPCR = {.count = 0};
    
    TPM2B_PRIVATE *outPrivate = nullptr;
    TPM2B_PUBLIC *outPublic = nullptr;
    TPM2B_CREATION_DATA *creationData = nullptr;
    TPM2B_DIGEST *creationHash = nullptr;
    TPMT_TK_CREATION *creationTicket = nullptr;
    
    rc = Esys_Create(g_esys_ctx,
                    srkHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive,
                    &inPublic,
                    &outsideInfo,
                    &creationPCR,
                    &outPrivate,
                    &outPublic,
                    &creationData,
                    &creationHash,
                    &creationTicket);
    
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to create sealed object: " 
                    << Tss2_RC_Decode(rc) << std::endl;
        Esys_FlushContext(g_esys_ctx, policySessionPCR);
        Esys_FlushContext(g_esys_ctx, srkHandle);
        Esys_Free(policyDigestPCR);
        return false;
    }
    
    // Load the sealed object into TPM
    ESYS_TR loadedHandle;
    rc = Esys_Load(g_esys_ctx,
                    srkHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    outPrivate,
                    outPublic,
                    &loadedHandle);
    
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to load sealed object: " 
                    << Tss2_RC_Decode(rc) << std::endl;
        Esys_FlushContext(g_esys_ctx, policySessionPCR);
        Esys_FlushContext(g_esys_ctx, srkHandle);
        Esys_Free(outPrivate);
        Esys_Free(outPublic);
        Esys_Free(creationData);
        Esys_Free(creationHash);
        Esys_Free(creationTicket);
        Esys_Free(policyDigestPCR);
        return false;
    }
    
    // Make the handle persistent
    ESYS_TR persistentHandleEsys;
    rc = Esys_EvictControl(g_esys_ctx,
                            ESYS_TR_RH_OWNER,
                            loadedHandle,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            persistentHandle,
                            &persistentHandleEsys);
    
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to make handle persistent: " 
                    << Tss2_RC_Decode(rc) << std::endl;
        Esys_FlushContext(g_esys_ctx, loadedHandle);
        Esys_FlushContext(g_esys_ctx, policySessionPCR);
        Esys_FlushContext(g_esys_ctx, srkHandle);
        Esys_Free(outPrivate);
        Esys_Free(outPublic);
        Esys_Free(creationData);
        Esys_Free(creationHash);
        Esys_Free(creationTicket);
        Esys_Free(policyDigestPCR);
        return false;
    }
    
    std::cout << "Auto unlock-key successfully sealed with PCR values. Persistent handle: 0x" << std::hex << persistentHandle << std::dec << std::endl;
    
    // Cleanup
    Esys_FlushContext(g_esys_ctx, loadedHandle);
    Esys_FlushContext(g_esys_ctx, policySessionPCR);
    Esys_FlushContext(g_esys_ctx, srkHandle);
    Esys_Free(outPrivate);
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(policyDigestPCR);
    
    return true;
}

extern "C"
{ 
    extern int main_pcr_oracle(int argc, char **argv);
}


void init_pcr_selection(TPML_PCR_SELECTION &pcr_selection, std::vector<int> pcrindices) {
    memset(&pcr_selection, 0, sizeof(pcr_selection));
    pcr_selection.count = 1;
    pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcr_selection.pcrSelections[0].sizeofSelect = 3;

    for (auto i : pcrindices)
    {
       pcr_selection.pcrSelections[0].pcrSelect[i / 8] |= (1 << (i % 8));
    }
}

std::vector<uint8_t> retrieve_current_pcr_values_concat(TPML_PCR_SELECTION pcr_selection) 
{
    std::vector<uint8_t> pcr_values;
    TPML_DIGEST *pcr_digest = nullptr;

    // Read PCR values
    TSS2_RC rc = Esys_PCR_Read(
        g_esys_ctx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &pcr_selection,
        0,
        0,
        &pcr_digest
    );

    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_PCR_Read failed: 0x" << std::hex << rc << std::endl;
        return {};
    }
    
    // PCR 15 is extended by garbage right after unsealing to prevent unsealing a second time
    // Copy PCR values to output vector
    for (int i = 0; i < pcr_digest->count; ++i) {
        if (pcr_list[i]==15)
        {
            for(int j=0;j<pcr_digest->digests[i].size;j++)
                pcr_values.push_back(0);
        }
        else
        {
            for(int j=0;j<pcr_digest->digests[i].size;j++)
                pcr_values.push_back(pcr_digest->digests[i].buffer[j]);
        }
    }

    // Clean up
    Esys_Free(pcr_digest);

    return pcr_values;
}

std::string pcr_list_to_string(std::vector<int> pcr_List)
{
    std::string result;
    for (auto i : pcr_List) {
        result += std::to_string(i) + ",";
    }
    if (!result.empty()) {
        result.pop_back(); // Remove the trailing comma
    }
    return result;
}

std::vector<uint8_t> predicted_pcr_conc;
extern "C" void pcr_result_callback(const char *data,int len)
{
    for (int i = 0; i < len; ++i)
        predicted_pcr_conc.push_back(*data++);
}



// Helper function to trim whitespace from both ends
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, last - first + 1);
}

// Helper function to split a string by whitespace
std::vector<std::string> split(const std::string& str) {
    std::vector<std::string> tokens;
    std::istringstream iss(str);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}



bool modifyCrypttab(bool dryrun) {
    std::string deviceName = root_partition_name;
    const std::string& crypttabPath = "/etc/crypttab";
    std::ifstream inFile(crypttabPath);
    if (!inFile.is_open()) {
        std::cerr << "Error: Cannot open " << crypttabPath << std::endl;
        return false;
    }

    std::vector<std::string> lines;
    std::string line;
    bool deviceFound = false;

    // Read and process each line
    while (std::getline(inFile, line)) {
        // Skip empty lines and comments
        std::string trimmed = line;
        trimmed.erase(0, trimmed.find_first_not_of(" \t"));
        
        if (trimmed.empty() || trimmed[0] == '#') {
            lines.push_back(line);
            continue;
        }

        // Parse the line into columns
        std::istringstream iss(line);
        std::string name, source, keyfile, options;
        iss >> name >> source >> keyfile >> options;

        // Check if this is the target device
        if (name == deviceName) {
            deviceFound = true;
            
            // Reconstruct the line with /root.key as keyfile
            std::ostringstream oss;
            oss << name << " " << source << " /root.key";
            
            // Preserve options if they exist
            if (!options.empty()) {
                oss << " " << options;
            }
            
            lines.push_back(oss.str());
            if (!dryrun)
            std::cout << "Modified entry for device: " << deviceName << std::endl;
        } else {
            lines.push_back(line);
        }
    }
    inFile.close();

    if (!deviceFound) {
        std::cerr << "Error: Device '" << deviceName << "' not found in " << crypttabPath << std::endl;
        return false;
    }

    if (dryrun) return true;

    // Write back to the file
    std::ofstream outFile(crypttabPath);
    if (!outFile.is_open()) {
        std::cerr << "Error: Cannot write to " << crypttabPath << std::endl;
        return false;
    }

    for (const auto& l : lines) {
        outFile << l << "\n";
    }
    outFile.close();
    chmod(crypttabPath.c_str(),0755);

    std::cout << "Successfully updated " << crypttabPath << std::endl;
    return true;
}



struct CommandResult {
    std::string output;
    int exit_status;
};

CommandResult exec_status(const std::string& command) {
    if (verbosity) 
    {
        std::cout << ".> " << command << std::endl;
    }
//    const char* cmd = (command + " 2>&1").c_str();
    const char* cmd = (command).c_str();
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    
    CommandResult result;
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
        result.output += buffer;
    }
    
    // Get the exit status
    result.exit_status = pclose(pipe.release());
    
    return result;
}

std::string exec(const std::string&command)
{
    return exec_status(command).output;
}

#include <sys/wait.h>
class Pipe {
private:
    int fd[2];
    
public:
    Pipe() {
        if (pipe(fd) == -1) {
            throw std::runtime_error("pipe() failed");
        }
    }
    
    ~Pipe() {
        closeRead();
        closeWrite();
    }
    
    int getRead() const { return fd[0]; }
    int getWrite() const { return fd[1]; }
    
    void closeRead() {
        if (fd[0] != -1) {
            close(fd[0]);
            fd[0] = -1;
        }
    }
    
    void closeWrite() {
        if (fd[1] != -1) {
            close(fd[1]);
            fd[1] = -1;
        }
    }
};

std::string exec_with_input(const std::string& command, const std::string& input="") {
    Pipe stdin_pipe;  // Parent writes, child reads
    Pipe stdout_pipe; // Child writes, parent reads
    
    pid_t pid = fork();
    
    if (pid == -1) {
        throw std::runtime_error("fork() failed");
    }
    
    if (pid == 0) { // Child process
        // Redirect stdin and stdout
        dup2(stdin_pipe.getRead(), STDIN_FILENO);
        dup2(stdout_pipe.getWrite(), STDOUT_FILENO);
        
        // Close all pipe ends in child
        stdin_pipe.closeWrite();
        stdin_pipe.closeRead();
        stdout_pipe.closeRead();
        stdout_pipe.closeWrite();
        
        // Execute the command
        execl("/bin/sh", "sh", "-c", command.c_str(), nullptr);
        
        // If execl fails
        std::cerr << "execl() failed" << std::endl;
        exit(1);
    } else { // Parent process
        // Close unused ends
        stdin_pipe.closeRead();
        stdout_pipe.closeWrite();
        
        // Write input to child
        ssize_t bytes_written = write(stdin_pipe.getWrite(), input.c_str(), input.size());
        if (bytes_written == -1) {
            throw std::runtime_error("write() to child failed");
        }
        
        // Close stdin to signal EOF
        stdin_pipe.closeWrite();
        
        // Read output from child
        std::string result;
        std::array<char, 256> buffer;
        ssize_t bytes_read;
        
        while ((bytes_read = read(stdout_pipe.getRead(), buffer.data(), buffer.size())) > 0) {
            result.append(buffer.data(), bytes_read);
        }
        
        if (bytes_read == -1) {
            throw std::runtime_error("read() from child failed");
        }
        
        // Wait for child to complete
        int status;
        waitpid(pid, &status, 0);
        
        return result;
    }
}


std::string findRootDevice(const Json::Value& device, const std::string& currentName = "") {
    // Check if this device is mounted at /
    if (device.isMember("mountpoint") && device["mountpoint"].asString() == "/") {
        root_partition_name = device["name"].asString();
        return currentName;
    }
    
    // Check children recursively
    if (device.isMember("children")) {
        for (const auto& child : device["children"]) {
            std::string childName = child.isMember("name") ? child["name"].asString() : "";
            std::string found = findRootDevice(child, childName);
            if (!found.empty()) {
                // If we found the root device and we're at the parent level, return our UUID
                if (device.isMember("uuid") && !device["uuid"].isNull()) {

                    root_device_name = device["name"].asString();
                    root_device_uuid =  device["uuid"].asString();

                    return "PARENT_UUID:" + device["uuid"].asString();
                }
                return found;
            }
        }
    }
    
    return "";
}

bool find_root_partition_data() {
    try {
        // Execute lsblk command
        std::string output = exec("lsblk -J -o MOUNTPOINT,UUID,NAME");
        
        // Parse JSON
        Json::CharReaderBuilder builder;
        Json::Value root;
        std::string errs;
        std::istringstream s(output);
        
        if (!Json::parseFromStream(builder, s, &root, &errs)) {
            throw std::runtime_error("Failed to parse JSON: " + errs);
        }
        
        // Navigate through blockdevices
        if (!root.isMember("blockdevices")) {
            throw std::runtime_error("No blockdevices found in lsblk output");
        }
        
        for (const auto& device : root["blockdevices"]) {
            std::string result = findRootDevice(device);
            if (result.find("PARENT_UUID:") == 0) {
                return true; // Remove "PARENT_UUID:" prefix
            }
        }
        
        return false; // No parent UUID found
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        adderror("Failed to get parent UUID of root device");
        return false;
    }
}

bool create_folder(const std::string& folderPath) {
    if (mkdir(folderPath.c_str(), 0755) == 0) {
        return true;
    } else {
        if (errno == EEXIST) {
//            std::cout << "Folder '" << folderPath << "' already exists." << std::endl;
            return true;
        } else {
            std::cout << "Error: Failed to create folder '" << folderPath << "'. Error: " << strerror(errno) << std::endl;
            return false;
        }
    }
}        

int getFileSize(const std::string& filepath) {
    try {
        return std::filesystem::file_size(filepath);
    } catch (const std::filesystem::filesystem_error& e) {
        return -1; // Return -1 on error
    }
}


bool is_dracut_available() {
    // Check if dracut executable exists in common locations
    std::vector<std::string> possible_paths = {
        "/usr/bin/dracut",
        "/usr/sbin/dracut",
        "/bin/dracut",
        "/sbin/dracut"
    };
    
    for (const auto& path : possible_paths) {
        if (fs::exists(path) && fs::is_regular_file(path)) {
            return true;
        }
    }
    return false;
}

bool has_dracut_config() {
    // Check for dracut configuration directory
    if (fs::exists("/etc/dracut.conf") || fs::exists("/etc/dracut.conf.d")) {
        return true;
    }
    
    // Check for dracut modules directory
    if (fs::exists("/usr/lib/dracut") || fs::exists("/usr/lib/dracut/modules.d")) {
        return true;
    }
    
    return false;
}

enum class BootLoader {
    SYSTEMD_BOOT,
    GRUB,
    UNKNOWN
};

BootLoader check_bootloader() {
    std::string output = exec("bootctl status 2>&1");
    
    // Check for systemd-boot indicators
    if (output.find("Product: systemd-boot") != std::string::npos) {
        return BootLoader::SYSTEMD_BOOT;
    }
    
    // Check for GRUB indicators
    if (output.find("Product: GRUB") != std::string::npos) {
        return BootLoader::GRUB;
    }
    
    // If bootctl runs but doesn't show systemd-boot, likely GRUB
    if (output.find("Firmware:") != std::string::npos &&
        output.find("systemd-boot") == std::string::npos) {
        return BootLoader::GRUB;
    }
        
    return BootLoader::UNKNOWN;
}

bool predictpcrs();

bool checkTpm2Tools() {
    std::string command = "which tpm2_getrandom tpm2_pcrread >/dev/null 2>&1";
    int result = system(command.c_str());
    return (result == 0);
}

bool is_initramfs_tools_installed()
{
    return fs::exists("/usr/share/initramfs-tools/init");
}

void system_checks()
{
    if (getuid() != 0) 
    {
        adderror("You need to be root to run this program.");
        return;
    }

    if (!checkTpm2Tools())
    {
        adderror("tpm2 tools must be installed");
    }

    if (!is_dracut_available() || !has_dracut_config())
    {
        adderror("Only systems with dracut initRAMFS generator are supported. (Dracut is default on Ubuntu from release 25.10)");
    }

    if (is_initramfs_tools_installed())
    {
        adderror("Fully remove initramfs-tools Ubuntu package and do \"apt autoremove\"");
    }

    if (check_bootloader()!=BootLoader::SYSTEMD_BOOT) adderror("System wasn't booted with systemd-boot. Install systemd-boot then reboot before retrying.");

    if (retrieve_current_pcr_values_concat(pcrSelection).empty()) adderror("Can't access TPM2");

//    if (predictpcrs()==false) adderror("PCR prediction doesn't work."); // can't call  twice

    if (root_device_name.empty() || root_device_uuid.empty())
    {
        adderror("Failed to find root partition details.");
    }

    if (modifyCrypttab(true)==false)
    {
        adderror("Can't modify /etc/crypttab");
    }

    // auto res = checkCrypttabForKeyfiles();
    // if (res.empty()==false)
    // {
    //     adderror("/etc/crypttab contains keyfiles, which are included in the initRAMFS. The initRAMFS is not ecrypted when using systemd-boot.");
    // }
}

std::string getPassword(const std::string& prompt = "Enter password: ") {
    std::cout << prompt;
    
    std::string password;
    
    // Linux/Unix implementation
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::getline(std::cin, password);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    
    std::cout << std::endl;
    return password;
}

bool extra_luks_key_setup()
{
    if (getFileSize(ROOT_KEY_FILE)==32)
    {
        std::cout << "note: extra key on root partition has been added before.\n";
        return true;
    }

    std::cout << "Enter passphrase for /dev/" << root_device_name << " : ";

    std::string password = getPassword();
    Tempfile passwdfile = Tempfile(password);

    std::string command = "cryptsetup luksOpen --test-passphrase /dev/"+root_device_name+" --key-file "+passwdfile.get_path()+" --verbose";

    auto result = exec(command.c_str());
    if (result.find("Command successful.") == std::string::npos) {
        std::cout << result << std::endl;
        std::cout<<"Wrong password." << std::endl;
        exit(0);
        return false;
    }

    exec((std::string("dd if=/dev/random of=") + ROOT_KEY_FILE + " bs=32 count=1").c_str());
    exec(std::string("chmod 600 ")+ROOT_KEY_FILE);
    if (getFileSize(std::string(ROOT_KEY_FILE))!=32)
    {
        adderror("Failed to create root keyfile");
        return false;        
    }

//    std::cout << "Password accepted." << std::endl;
    if (result.find("Key slot 0 unlocked.")!=std::string::npos) {
        std::cout << "Moving your password from slot 0 to another slot in the LUKS header\n";

        // add a second keys of the user's password
        command = "cryptsetup luksAddKey --iter-time=500 --key-file "+passwdfile.get_path()+" --verbose /dev/"+root_device_name+" "+passwdfile.get_path();
        result = exec(command.c_str());
        std::cout << result << std::endl;
        if (result.find("Command successful.")==std::string::npos)
        {
            result = exec(command.c_str());  
            remove("ROOT_KEY_FILE");
            adderror("Failed to move password from slot 0 to another slot");
            return false;
        }

        std::cout << "Deleting your password from slot 0\n";
         // delete slot 0 to make space for the generated key
        command = "cryptsetup luksKillSlot /dev/"+root_device_name+" 0 --key-file "+passwdfile.get_path()+" --verbose";
        result = exec(command.c_str());
        if (result.find("Command successful.")==std::string::npos)
        {
            std::cout << result << std::endl;
            adderror("deleting luks key slot failed");
            remove("ROOT_KEY_FILE");
            return false;
        }
    }

    std::cout << "Adding a larger key to root partition for fast and secure unlocking\n";
    command = "cryptsetup luksAddKey --iter-time=5   --verbose  --key-file "+passwdfile.get_path()+" /dev/"+root_device_name+" "+ROOT_KEY_FILE;
    result = exec(command.c_str()); 
    if (result.find("Command successful.") == std::string::npos) {
        std::cout << result << std::endl;
        remove("ROOT_KEY_FILE");
        adderror("Failed to add root keyfile to LUKS header");
        return false;
    }

    return true;
}


bool getTPMHandleAddress(bool only_from_file)
{
    std::ifstream inFile(DATA_DIR "/persistent_handle.bin");
    if (inFile.is_open()) {
        inFile.read((char *)&persistent_handle.handle, sizeof(persistent_handle.handle));
    }
    else
    {
        if (only_from_file)
        {
            adderror("NVRAM address hasn't been assigned. Have you run setup?");
            return false;
        }
        persistent_handle.handle = find_free_handle();
        if  (persistent_handle.handle==0)
        {
            adderror("Could not find a free slot in NVRAM");
            return false;
        }
        std::ofstream outFile(DATA_DIR "/persistent_handle.bin");
        if (!outFile.is_open()) {
            adderror("Failed to write persistent handle to file");
            return false;
        }
        outFile.write((const char *)&persistent_handle.handle, sizeof(persistent_handle.handle));
    }
    snprintf(persistent_handle.text, sizeof(persistent_handle.text), "0x%x", persistent_handle.handle);
    return true;
}




bool install_hooks()
{
    if (!is_dracut_available()) return false;

    auto retriever = 
    std::string(
        "#!/usr/bin/bash\n"
        "echo Luksury is unsealing root encryption key\n"
        "echo 'luksury is unsealing root encryption key' >> /run/initramfs/log/luksury.log\n"
        "modprobe -a -q tpm_crb >/dev/null 2>&1\n"
        "tpm2_pcrread >>/run/initramfs/log/luksury.log\n"
        "tpm2_unseal -c ")+persistent_handle.text+" -p pcr:sha256:"+pcr_list_to_string(pcr_list)+" -o /root.key>>/run/initramfs/log/luksury.log 2>&1\n"
        "tpm2_pcrextend 15:sha256=6666666666666666666666666666666666666666666666666666666666666666\n"
        "if [ ! -f \"/root.key\" ]\n"
        " then\n"
        " echo Luksury could not decrypt system volume automatically\n"
        " echo Luksury could not decrypt system volume automatically >> /run/initramfs/log/luksury.log\n"
        " echo\n"
        " echo\n"
        " fi\n";
    
    mkdir(DRACUT_PATH,0755);
    if (!saveFile(DRACUT_PATH "/luksury_retrieve.sh",retriever,0755)) return false;

    auto installer = (
        "#!/bin/bash\n"
        "check() {\n"
        "    return 0\n"
        "}\n"
        "depends() {\n"
        "    return 0\n"
        "}\n"
        "install() {\n"
        "   inst_multiple tpm2_unseal tpm2_pcrread\n"
        "   inst_libdir_file \"libtss2-tct-device.so*\"\n"
        "   inst_hook pre-udev 10 \"$moddir/luksury_retrieve.sh\"\n"
        "}\n"
        );
    if (!saveFile(DRACUT_PATH "/module-setup.sh", installer,0755)) return false;

    std::cout << "initRAMFS hook for retrieving key from TPM2 installed\n";

    std::string no_emergency_shell = "omit_dracutmodules+=\" debug rescue \"\n";
    if  (saveFile("/usr/lib/dracut/dracut.conf.d/80-luksury.conf",no_emergency_shell,0x644)) 
    {
        std::cout << "Emergency shells disabled\n";
    }

    return true;
}

bool install_auto_update_arch()
{
    if (fs::exists("/etc/pacman.d"))
    {

        std::string  postupdate = 
        "[Trigger]\n"
        "Operation = Install\n"
        "Operation = Upgrade\n"
        "Type = Package\n"
        "Target = linux\n"
        "Target = fwupd\n"
        "Target = systemd\n"
        "Target = edk2-shell\n"
        "\n"
        "[Action]\n"
        "Description =Updating Luksury EFI and PCRs\n"
        "When = PostTransaction\n"
        "Exec = /usr/bin/luksury update\n";

        mkdir("/etc/pacman.d/hooks",0x755);

        if (!saveFile("/etc/pacman.d/hooks/99-luksury.hook",postupdate,0755,false))
        {
            return false;
        }
        return true;
    }
    return false;
}

bool install_auto_update()
{
    std::string updatecommand = "#!/bin/sh\nluksury update\n";
    if (!saveFile("/etc/initramfs/post-update.d/zzz-luksury",updatecommand,0755,false))
    {
        // ubuntu failed, try arch
           
        return  install_auto_update_arch();
    }
    return true;
}


bool initial_setup()
{
    find_root_partition_data();
    system_checks();
    if (errors.size()) return false;

    if (create_folder(DATA_DIR)==false) return false;

    if (!extra_luks_key_setup()) return false;

    if (!getTPMHandleAddress(false)) return false;

    if (!install_hooks()) return false;

    if (!modifyCrypttab(false)) return false;

    if (!install_auto_update())
    {
        std::cout << "Warning: Failed to install auto update for initrd or kernel updates\n";
    }

    if (getFileSize("/usr/sbin/update-initramfs")>0)
    {
        int res = system("/usr/sbin/update-initramfs -u");
        return true;
//        return update_pcrs();
    }
    else
    {
        std::cout << "\nTo complete setup, please regenerate initRAMFS, then run \"sudo luksury update\"\n";
    }

    return true;
}

bool predictpcrs()
{
    auto pcr_string = pcr_list_to_string(pcr_list);
    char *args[]={"pcr-oracle","--from","eventlog","-F","luksury",&pcr_string[0],"--next-kernel","auto"};
    predicted_pcr_conc.clear();
    main_pcr_oracle(8, (args));
    if (predicted_pcr_conc.size()!=pcr_list.size() * SHA256_DIGEST_LENGTH)
    {
//        adderror("PCR prediction failed.");
        std::cout << "Warning: pcr prediction failed.\n";
//        return false;
    }
    return true;
}


int update_pcrs()
{
    auto current_pcr_values = retrieve_current_pcr_values_concat(pcrSelection);
    std::cout << "luksury is updating PCR values for auto-unlocking\n";
    if (!predictpcrs())
    {
        std::cout << "using current PCRs\n";
        predicted_pcr_conc = current_pcr_values;
    }
    else
    {
        if (current_pcr_values != predicted_pcr_conc)
        {
            std::cout << "predicted PCR values do not match current (system may have been updated)\n";
        }
        else
        {
            std::cout << "predicted PCR values = current\n";
        }
    }

    if (!getTPMHandleAddress(true)) return 1;

    auto rootkey = loadFile( ROOT_KEY_FILE );
    if (rootkey.size()!=32)
    {
        adderror("Can't access stored keyfile. Have you run setup?");
        return 1;
    }

    std::vector<TPM2_HANDLE> handles = get_tpm_persistent_handles();
    if (std::find(handles.begin(),handles.end(),persistent_handle.handle)!=handles.end()  ) {
        evict_persistent(persistent_handle.handle);
    }

    if (!seal_secret_to_persistent( persistent_handle.handle, rootkey, pcrSelection, predicted_pcr_conc))
    {
        adderror("TPM keyfile PCR update failed.");
    }

    Esys_Finalize(&g_esys_ctx);
    return 0;
}

int pcr_test()
{
    if (check_bootloader()!=BootLoader::SYSTEMD_BOOT) 
    {
        adderror("System wasn't booted with systemd-boot. Install systemd-boot then reboot before retrying.");
        return 1;
    }


    std::cout << "Comparing predicted PCRs with current ones\n";
    auto current_pcr_values = retrieve_current_pcr_values_concat(pcrSelection);
    if (!predictpcrs())
    {
        std::cout << "using current PCRs\n";
        predicted_pcr_conc = current_pcr_values;
    }
    else
    {
        if (current_pcr_values != predicted_pcr_conc)
        {
            std::cout << "predicted PCR values do not match current (system may have been updated)\n";

            auto pcr_string = pcr_list_to_string(pcr_list);
            char *args[]={"pcr-oracle","--from","eventlog","-F","tpm2-tools","all","--next-kernel","auto"};
            predicted_pcr_conc.clear();
            main_pcr_oracle(8, (args));


        }
        else
        {
            std::cout << "predicted PCR values = current\n";
        }
    }
    return 0;
}

int main(int argc, char* argv[])
{
    // commands: --help, setup, remove, update
    if (argc !=2) {
        std::cout << "Usage: " << argv[0] << " [setup|remove|update|pcrtest]" << std::endl;
        std::cout << "\nLUKSury is a utility, which adds a generated key to the root file system LUKS partition, and automatically unlocks the voluime without the need to enter password.\n";
        std::cout << "The generated key is stored in TPM2 device, and can be unsealed only when measured boot PCR values match the expected values.\n";
        std::cout << "LUKSury automatically precomputes the PCR values after system updates, or by invoking \"sudo luksury update\"\n";
        std::cout << "Only your default kernel option,will boot without password prompt.\n";
        return 1;
    }

    if (getuid() != 0) 
    {
        adderror("You need to be root to run this program.");
        return 1;
    }
    TSS2_RC rc;
    rc = Esys_Initialize(&g_esys_ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error: Can't access TPM2. " << Tss2_RC_Decode(rc) << std::endl;
        return 1;
    }
    init_pcr_selection(pcrSelection, pcr_list);


    std::string command = argv[1];
    if (command == "setup") {
        return initial_setup();
    } else if (command == "remove") {
        return remove_luksury();
    } else if (command == "update") {
        return update_pcrs();
    } else if (command == "pcrtest") {
        return pcr_test();
    } else {
        std::cout << "Unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}