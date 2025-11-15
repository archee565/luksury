#include <iostream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cassert>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <memory>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <unistd.h>
#include <jsoncpp/json/json.h>  // Requires jsoncpp library

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

std::vector<int> pcr_list = {4,5,9};
#define DATA_DIR "/var/lib/luksury"
#define ROOT_KEY_FILE DATA_DIR "/root_keyfile.bin"
ESYS_CONTEXT *g_esys_ctx = nullptr;
std::vector<std::string> errors;
std::string root_device_name;
std::string root_device_uuid;
TPML_PCR_SELECTION pcrSelection;


#define ZERO(x) memset(&x,0, sizeof(x))

void adderror(const std::string& msg)
{
    std::cout << "Error: " << msg << std::endl; 
    errors.push_back(msg);
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


int seal_secret_to_persistent(
    uint32_t persistentHandle,
    const std::vector<uint8_t>& password,
    const TPML_PCR_SELECTION &pcrSelection,
    const std::vector<uint8_t>& pcrConcatenated)
    {
    
    
    auto digest = concatenated_to_digest(pcrConcatenated);
    
    // Create PCR policy
    ESYS_TR policySessionPCR;
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL
    };
   
    TSS2_RC rc;
    rc = Esys_StartAuthSession(g_esys_ctx,
                                ESYS_TR_NONE, ESYS_TR_NONE,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                NULL,
                                TPM2_SE_POLICY,
                                &symmetric,
                                TPM2_ALG_SHA256,
                                &policySessionPCR);
    
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to start auth session: " 
                    << Tss2_RC_Decode(rc) << std::endl;
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
    
    std::cout << "Password successfully sealed with PCR values!" << std::endl;
    std::cout << "Persistent handle: 0x" << std::hex << persistentHandle << std::dec << std::endl;
    
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

int delete_persistent_handle(TPM2_HANDLE persistentHandle) {
    TSS2_RC rc = Esys_EvictControl(
        g_esys_ctx,
        ESYS_TR_RH_OWNER,
        persistentHandle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        persistentHandle,
        nullptr
    );
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to delete persistent handle: 0x" << std::hex << persistentHandle << std::dec << std::endl;
        return 1;
    }
    std::cout << "Successfully deleted persistent handle: 0x" << std::hex << persistentHandle << std::dec << std::endl;
    return 0;
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

    // Copy PCR values to output vector
    for (int i = 0; i < pcr_digest->count; ++i) {
        for(int j=0;j<pcr_digest->digests[i].size;j++)
            pcr_values.push_back(pcr_digest->digests[i].buffer[j]);
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

bool editCrypttab(const std::string& uuid) {
    const std::string keyscriptParam = "keyscript=/var/lib/luksury/luksury_initrd.sh";
    const std::string crypttabPath = "/etc/crypttab";
    
    // Read the file
    std::ifstream inFile(crypttabPath);
    if (!inFile.is_open()) {
        std::cerr << "Error: Cannot open " << crypttabPath << std::endl;
        return false;
    }
    
    std::vector<std::string> lines;
    std::string line;
    bool foundAndModified = false;
    
    while (std::getline(inFile, line)) {
        std::string trimmedLine = trim(line);
        
        // Preserve empty lines and comments
        if (trimmedLine.empty() || trimmedLine[0] == '#') {
            lines.push_back(line);
            continue;
        }

        if (line.find("keyfile")!=std::string::npos)
        {
            adderror("/etc/crypttab contains keyfiles. These are unsafe, because they are stored in the initramfs.");
            return false;
        }
        
        // Parse the line
        std::vector<std::string> cols = split(trimmedLine);
        
        // crypttab format: <name> <device> <password> <options>
        // We need at least 2 columns (name and device)
        if (cols.size() >= 2) {
            // Check if this line contains the UUID
            if (cols[1].find(uuid) != std::string::npos) {
                // Ensure we have 4 columns
                while (cols.size() < 4) {
                    cols.push_back("-");
                }
                
                // Check if keyscript is already in the 4th column
                if (cols[3].find("keyscript=") == std::string::npos) {
                    // Add keyscript parameter
                    if (cols[3] == "-" || cols[3] == "none") {
                        cols[3] = keyscriptParam;
                    } else {
                        cols[3] += "," + keyscriptParam;
                    }
                    foundAndModified = true;
                }
                
                // Reconstruct the line
                std::ostringstream oss;
                for (size_t i = 0; i < cols.size(); ++i) {
                    if (i > 0) oss << " ";
                    oss << cols[i];
                }
                lines.push_back(oss.str());
            } else {
                lines.push_back(line);
            }
        } else {
            lines.push_back(line);
        }
    }
    inFile.close();
    
    if (!foundAndModified) {
        std::cerr << "Warning: UUID " << uuid << " not found or keyscript already present" << std::endl;
        return false;
    }
    
    // Get original file permissions
    struct stat fileStat;
    if (stat(crypttabPath.c_str(), &fileStat) != 0) {
        std::cerr << "Error: Cannot get file permissions" << std::endl;
        return false;
    }
    
    // Write to temporary file
    std::string tempPath = crypttabPath + ".tmp";
    std::ofstream outFile(tempPath);
    if (!outFile.is_open()) {
        std::cerr << "Error: Cannot create temporary file" << std::endl;
        return false;
    }
    
    for (const auto& l : lines) {
        outFile << l << "\n";
    }
    outFile.close();
    
    // Set same permissions on temp file
    if (chmod(tempPath.c_str(), fileStat.st_mode) != 0) {
        std::cerr << "Error: Cannot set permissions on temporary file" << std::endl;
        remove(tempPath.c_str());
        return false;
    }
    
    // Atomically replace original file
    if (0)
    if (rename(tempPath.c_str(), crypttabPath.c_str()) != 0) {
        std::cerr << "Error: Cannot replace original file" << std::endl;
        remove(tempPath.c_str());
        return false;
    }
    
    std::cout << "Successfully added keyscript parameter for UUID " << uuid << std::endl;
    return true;
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

std::string exec(const std::string& command, const std::string& input="") {
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

std::uintmax_t getFileSize(const std::string& filepath) {
    try {
        return std::filesystem::file_size(filepath);
    } catch (const std::filesystem::filesystem_error& e) {
        return -1; // Return -1 on error
    }
}

namespace fs = std::filesystem;

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

bool check_efivars()
{
   std::string path = "/sys/firmware/efi/efivars";
    
    for (const auto& entry : fs::directory_iterator(path)) {
        if (entry.path().filename().string().find("LoaderInfo") == 0) {
//            std::cout << "Found: " << entry.path() << std::endl;
            return true;
        }
    }    
    return false;
}

bool predictpcrs();

void system_checks()
{
    if (getuid() != 0) 
    {
        adderror("You need to be root to run this program.");
        return;
    }

    if (!is_dracut_available() || !has_dracut_config())
    {
        adderror("Only systems with dracut initRAMFS generator are supported. (Dracut is default on Ubuntu from release 25.10)");
    }

    if (!check_efivars()) adderror("System wasn't booted with systemd-boot. Install systemd-boot then reboot before retrying.");

    if (retrieve_current_pcr_values_concat(pcrSelection).empty()) adderror("Can't access TPM2");

    if (getFileSize("/boot/initrd.img")<1) adderror("Can't access /boot/initrd.img");
    if (getFileSize("/boot/vmlinuz")<1) adderror("Can't access /boot/vmlinuz");

    if (predictpcrs()==false) adderror("PCR prediction doesn't work.");

    if (root_device_name.empty() || root_device_uuid.empty())
    {
        adderror("Failed to find root partition details.");
    }
}

bool initial_setup()
{
    system_checks();
    if (errors.size()) return false;

    if (create_folder(DATA_DIR)==false) return false;


    if (getFileSize(ROOT_KEY_FILE)==32)
    {
        std::cout << "note: extra key on root partition has been added before.\n";
        return true;
    }
    std::string user_password = "a";

    std::string command = "cryptsetup luksOpen --test-passphrase /dev/"+root_device_name+" --key-file - --tries=1 --verbose";

    auto result = exec(command.c_str(),user_password);
    std::cout << result << std::endl;
    if (result.find("Command successful.") == std::string::npos) {
        std::cout<<"Wrong password." << std::endl;
        exit(0);
        return false;
    }

    exec((std::string("dd if=/dev/random of=") + ROOT_KEY_FILE + " bs=32 count=1").c_str());
    if (getFileSize(std::string(ROOT_KEY_FILE))!=32)
    {
        adderror("Failed to create root keyfile");
        return false;        
    }

//    std::cout << "Password accepted." << std::endl;
    if (result.find("Key slot 0 unlocked.")!=std::string::npos) {
        std::cout << "Moving your password from slot 0 to another slot in the LUKS header\n";

        // add a second keys of the user's password
        command = "cryptsetup luksAddKey --iter-time=500 /dev/"+root_device_name+" --key-file - --tries=1";
        result = exec(command.c_str(),user_password);  
        std::cout << result << std::endl;

         // delete slot 0 to make space for the generated key
        command = "cryptsetup luksKillSlot /dev/"+root_device_name+" 0 --key-file - --tries=1";
        result = exec(command.c_str(),user_password);
        std::cout << result << std::endl;
    }

    std::cout << "Adding a larger key to root partition for fast and secure unlocking\n";
    command = "cryptsetup luksAddKey --iter-time=5 /dev/"+root_device_name+" --key-file "ROOT_KEY_FILE" --tries=1 --verbose";
    result = exec(command.c_str()); 
    std::cout << result << std::endl;
    if (result.find("Command succesful.") == std::string::npos) {
        remove("ROOT_KEY_FILE");
        adderror("Failed to add root keyfile to LUKS header");
        return false;
    }

    if (editCrypttab(root_device_uuid)==false)
    {
        return false;
    }


    return true;
}

bool predictpcrs()
{
    auto pcr_string = pcr_list_to_string(pcr_list);
    char *args[]={"pcr-oracle","--from","eventlog","-F","luksury",&pcr_string[0]};
    predicted_pcr_conc.clear();
    main_pcr_oracle(6, (args));
    if (predicted_pcr_conc.size()!=pcr_list.size() * SHA256_DIGEST_LENGTH)
    {
        adderror("PCR prediction failed.");
        return false;
    }
    return true;
}


//todo: test luks optimizer, save persistent handle slot, install hooks

bool update_pcrs()
{
}


int main(int argc, char* argv[])
{
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
    find_root_partition_data();

    initial_setup();
    return 0;


    predictpcrs();


    auto current_pcr_concat = retrieve_current_pcr_values_concat(pcrSelection);

    std::cout<<"size: " << predicted_pcr_conc.size() << " data:" << std::hex << std::setfill('0') << std::setw(2);
    for (auto byte : predicted_pcr_conc) {
        std::cout << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
    
    std::cout<<"size: " << current_pcr_concat.size() << " data:" << std::hex << std::setfill('0') << std::setw(2);
    for (auto byte : current_pcr_concat) {
        std::cout << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;



    auto handle = find_free_handle();
    seal_secret_to_persistent( handle, {'h','e','l','l','o',0}, pcrSelection, predicted_pcr_conc);
//    delete_persistent_handle(handle);

    Esys_Finalize(&g_esys_ctx);
    if (errors.size())
    {
        for (const auto& err : errors) {
            std::cerr << "Error: " << err << std::endl;
        }
        return 1;
    }
    return 0;
}