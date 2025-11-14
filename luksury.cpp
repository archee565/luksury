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
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <jsoncpp/json/json.h>  // Requires jsoncpp library

#include <openssl/sha.h>  
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>

/*
Checklist: 
 - booted by systemd or grub
 - is root
 - Dracut system?
 - TPM2.0 support,tools ?
 - root encrypted, found?
 - PCR prediction testing
*/

ESYS_CONTEXT *g_esys_ctx = nullptr;
std::vector<std::string> errors;
std::string root_device_name;
std::string root_device_uuid;

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


// Main function: seal secret into a persistent handle using precomputed PCR digest.
// Parameters:
// - esys: ESAPI context
// - persistentHandle: desired persistent handle (e.g. 0x81010001). Must be free or you will need to Evict first.
// - secret: bytes of data to seal
// - pcrSelection: TPML_PCR_SELECTION describing which PCR indices & hash algs the digest corresponds to
// - pcrDigestBytes: the precomputed PCR composite digest (for the supplied pcrSelection) — raw bytes (e.g. SHA256 length when SHA256 used)
// NOTE: caller must have sufficient rights (owner) to call EvictControl to make persistent.
int seal_secret_to_persistent_bad(
    uint32_t persistentHandle,
    const std::vector<uint8_t>& secret,
    const TPML_PCR_SELECTION &pcrSelection,
    const std::vector<uint8_t>& pcrConcatenated
) {
    // 1) Start a trial policy session to compute the policy digest for PolicyPCR.
    ESYS_TR sessionTrial = ESYS_TR_NONE;
	static const TPMT_SYM_DEF symmetric = {
		.algorithm = TPM2_ALG_AES,
		.keyBits = { .aes = 128 },
		.mode = { .aes = TPM2_ALG_CFB }
	};

    TSS2_RC rc = Esys_StartAuthSession(
        g_esys_ctx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,ESYS_TR_NONE, ESYS_TR_NONE,
        0,
        TPM2_SE_TRIAL, &symmetric, TPM2_ALG_SHA256,
        &sessionTrial
    );
    if (check_rc(rc, "Esys_StartAuthSession (trial)")) return 1;

    // Prepare TPM2B_DIGEST for the PCR digest input to PolicyPCR:
    TPM2B_DIGEST pcrDigest = concatenated_to_digest(pcrConcatenated);

    // call PolicyPCR with the precomputed digest and selection
    rc = Esys_PolicyPCR(
        g_esys_ctx,
        sessionTrial,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &pcrDigest,
        const_cast<TPML_PCR_SELECTION*>(&pcrSelection)
    );
    if (check_rc(rc, "Esys_PolicyPCR")) return 1;

    // Retrieve the resulting policyDigest
    TPM2B_DIGEST *policyDigest = nullptr;
    rc = Esys_PolicyGetDigest(
        g_esys_ctx,
        sessionTrial,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &policyDigest
    );
    if (check_rc(rc, "Esys_PolicyGetDigest")) return 1;

    // 2) Create a sealed object template with authPolicy set to policyDigest
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    inSensitive.size = sizeof(TPM2B_SENSITIVE_CREATE);
    inSensitive.sensitive.userAuth.size = 0; // no additional auth; policy protects usage
    // Put the secret in sensitive.data
    if (secret.size() > sizeof(inSensitive.sensitive.data.buffer)) {
        Esys_FlushContext(g_esys_ctx, sessionTrial);
        adderror("secret too large to store in TPM sensitive area");
        return 1;
    }
    inSensitive.sensitive.data.size = (UINT16)secret.size();
    if (!secret.empty()) memcpy(inSensitive.sensitive.data.buffer, secret.data(), secret.size());

    TPM2B_PUBLIC inPublic = {};
    inPublic.size = sizeof(TPM2B_PUBLIC);
    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;           // sealed data uses keyedhash type
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;           // name algorithm
    inPublic.publicArea.objectAttributes = (TPMA_OBJECT) (
        TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_USERWITHAUTH /* or 0 */  // we rely on policy, adjust as needed
        // Do NOT set DECRYPT/ENCRYPT if you only want sealed data accessible via Policy
    );
    // Set the authPolicy to the computed policy digest
    if (policyDigest->size > sizeof(inPublic.publicArea.authPolicy.buffer)) {
        Esys_FlushContext(g_esys_ctx, sessionTrial);
        Esys_Free(policyDigest);
        adderror("policy too large");
        return 1;
    }
    inPublic.publicArea.authPolicy.size = policyDigest->size;
    memcpy(inPublic.publicArea.authPolicy.buffer, policyDigest->buffer, policyDigest->size);

    // keyedHash parameters: no scheme (TPM2_ALG_NULL) for sealed data
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.unique.keyedHash.size = 0;

    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {}; // none
    // 3) Create the object under a storage primary key
    ESYS_TR primaryHandle = create_storage_primary(g_esys_ctx);

    TPM2B_PRIVATE *outPrivate = nullptr;
    TPM2B_PUBLIC *outPublic = nullptr;
    rc = Esys_Create(
        g_esys_ctx,
        primaryHandle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &inSensitive,
        &inPublic,
        &outsideInfo,
        &creationPCR,
        &outPrivate,
        &outPublic,
        nullptr, nullptr, nullptr
    );
    
    if (check_rc(rc, "Esys_Create")) return 0;

    // 4) Load the created object
    ESYS_TR objectHandle = ESYS_TR_NONE;
    rc = Esys_Load(
        g_esys_ctx,
        primaryHandle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        outPrivate,
        outPublic,
        &objectHandle
    );
    if (check_rc(rc, "Esys_Load")) return 0;

    // 5) Make the object persistent at persistentHandle (requires owner auth)
    // EvictControl: hierarchy ESYS_TR_RH_OWNER, objectHandle -> persistentHandle
    rc = Esys_EvictControl(
        g_esys_ctx,
        ESYS_TR_RH_OWNER,
        objectHandle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        persistentHandle,
        nullptr
    );
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_EvictControl failed (maybe handle already in use): 0x" << std::hex << rc << std::dec << "\n";
        // If handle already used you may want to call Esys_EvictControl to remove old object first.
        // Clean up and exit for this example.
        Esys_FlushContext(g_esys_ctx, objectHandle);
        Esys_FlushContext(g_esys_ctx, primaryHandle);
        Esys_Free(outPrivate);
        Esys_Free(outPublic);
        Esys_Free(policyDigest);
        Esys_FlushContext(g_esys_ctx, sessionTrial);
        adderror("Esys_EvictControl failed (maybe handle already in use):");
        return 1;
    }

    std::cout << "Sealed object made persistent at 0x" << std::hex << persistentHandle << std::dec << "\n";

    // 6) Cleanup: free created structures and flush contexts
    Esys_FlushContext(g_esys_ctx, objectHandle);
    Esys_FlushContext(g_esys_ctx, primaryHandle);
    Esys_Free(outPrivate);
    Esys_Free(outPublic);
    Esys_Free(policyDigest);
    Esys_FlushContext(g_esys_ctx, sessionTrial);
    return 0;
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

bool editCrypttab(const std::string& uuid, const std::string& crypttabPath = "/etc/crypttab") {
    const std::string keyscriptParam = "keyscript=/var/lib/luksury/luksury_initrd.sh";
    
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

std::string exec(const char* cmd, std::string input="") {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, input.size()==0?"r":"w"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    if (!input.empty()) {
        fwrite(input.c_str(), 1, input.size(), pipe.get());
    }


    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
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

bool getParentUUIDOfRootDevice() {
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


bool inputpasword()
{
    std::string command = "cryptsetup luksOpen --test-passphrase /dev/"+root_device_name+" --key-file - --tries=1 --verbose";

    auto result = exec(command.c_str(),"a");
    std::cout << result;
    if (result.find("Command succesful.") == std::string::npos) {
        std::cout<<"Wrong password." << std::endl;
        exit(0);
        return false;
    }
//    std::cout << "Password accepted." << std::endl;
    if (result.find("Key slot 0 unlocked.")!=std::string::npos) {
        std::cout << "Moving your password from slot 0 to another slot in the LUKS header\n";
        
        return true;
    }
    return true;
}


int main(int argc, char* argv[])
{
    getParentUUIDOfRootDevice();
    inputpasword();
//    std::cout << getParentUUIDOfRootDevice() << std::endl;
//    editCrypttab(getParentUUIDOfRootDevice());
    return 0;

    TSS2_RC rc;
    rc = Esys_Initialize(&g_esys_ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_Initialize failed: 0x" << std::hex << rc << std::endl;
        return 1;
    }

    std::vector<int> pcr_list = {4,5,9};
    TPML_PCR_SELECTION pcrSelection;
    init_pcr_selection(pcrSelection, pcr_list);

    auto pcr_string = pcr_list_to_string(pcr_list);
    char *args[]={"pcr-oracle","--from","eventlog","-F","luksury",&pcr_string[0]};
    predicted_pcr_conc.clear();
    main_pcr_oracle(6, (args));

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