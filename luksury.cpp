#include <iostream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cassert>
#include <iomanip>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

/*
Checklist: 
 - Dracut system?
 - TPM2.0 support,tools ?
 - root encrypted, found?
 - PCR prediction testing
*/

ESYS_CONTEXT *g_esys_ctx = nullptr;
#define ZERO(x) memset(&x,0, sizeof(x))

ESYS_CONTEXT *tss_esys_context() {
    ESYS_CONTEXT *ctx = nullptr;
    TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error initializing TSS context: " << rc << std::endl;
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
static void check_rc(TSS2_RC rc, const char *what) {
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << what << " failed: 0x" << std::hex << rc << std::dec << "\n";
        exit(1);
    }
}

// Convert std::vector<uint8_t> -> TPM2B_DIGEST
static TPM2B_DIGEST make_TPM2B_DIGEST(const std::vector<uint8_t>& v) {
    TPM2B_DIGEST d;
    if (v.size() > sizeof(d.buffer)) {
        std::cerr << "digest too large\n"; exit(1);
    }
    d.size = (UINT16)v.size();
    if (d.size) memcpy(d.buffer, v.data(), d.size);
    return d;
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
    check_rc(rc, "Esys_CreatePrimary");

    if (outPublic) {
        Esys_Free(outPublic);
    }
    return primaryHandle;
}

// Main function: seal secret into a persistent handle using precomputed PCR digest.
// Parameters:
// - esys: ESAPI context
// - persistentHandle: desired persistent handle (e.g. 0x81010001). Must be free or you will need to Evict first.
// - secret: bytes of data to seal
// - pcrSelection: TPML_PCR_SELECTION describing which PCR indices & hash algs the digest corresponds to
// - pcrDigestBytes: the precomputed PCR composite digest (for the supplied pcrSelection) — raw bytes (e.g. SHA256 length when SHA256 used)
// NOTE: caller must have sufficient rights (owner) to call EvictControl to make persistent.
void seal_secret_to_persistent(
    ESYS_CONTEXT *esys,
    uint32_t persistentHandle,
    const std::vector<uint8_t>& secret,
    const TPML_PCR_SELECTION &pcrSelection,
    const std::vector<uint8_t>& pcrDigestBytes
) {
    // 1) Start a trial policy session to compute the policy digest for PolicyPCR.
    ESYS_TR sessionTrial = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_NULL };
    TSS2_RC rc = Esys_StartAuthSession(
        esys,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        0, 0,
        0,
        TPM2_SE_TRIAL, &symmetric, TPM2_ALG_SHA256,
        &sessionTrial
    );
    check_rc(rc, "Esys_StartAuthSession (trial)");

    // Prepare TPM2B_DIGEST for the PCR digest input to PolicyPCR:
    TPM2B_DIGEST pcrDigest = make_TPM2B_DIGEST(pcrDigestBytes);

    // call PolicyPCR with the precomputed digest and selection
    rc = Esys_PolicyPCR(
        esys,
        sessionTrial,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &pcrDigest,
        const_cast<TPML_PCR_SELECTION*>(&pcrSelection)
    );
    check_rc(rc, "Esys_PolicyPCR");

    // Retrieve the resulting policyDigest
    TPM2B_DIGEST *policyDigest = nullptr;
    rc = Esys_PolicyGetDigest(
        esys,
        sessionTrial,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &policyDigest
    );
    check_rc(rc, "Esys_PolicyGetDigest");

    // 2) Create a sealed object template with authPolicy set to policyDigest
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    inSensitive.size = sizeof(TPM2B_SENSITIVE_CREATE);
    inSensitive.sensitive.userAuth.size = 0; // no additional auth; policy protects usage
    // Put the secret in sensitive.data
    if (secret.size() > sizeof(inSensitive.sensitive.data.buffer)) {
        std::cerr << "secret too large to store in TPM sensitive area\n";
        Esys_FlushContext(esys, sessionTrial);
        exit(1);
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
        std::cerr << "policy digest too large\n";
        Esys_FlushContext(esys, sessionTrial);
        Esys_Free(policyDigest);
        exit(1);
    }
    inPublic.publicArea.authPolicy.size = policyDigest->size;
    memcpy(inPublic.publicArea.authPolicy.buffer, policyDigest->buffer, policyDigest->size);

    // keyedHash parameters: no scheme (TPM2_ALG_NULL) for sealed data
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.unique.keyedHash.size = 0;

    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {}; // none
    // 3) Create the object under a storage primary key
    ESYS_TR primaryHandle = create_storage_primary(esys);

    TPM2B_PRIVATE *outPrivate = nullptr;
    TPM2B_PUBLIC *outPublic = nullptr;
    rc = Esys_Create(
        esys,
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
    check_rc(rc, "Esys_Create");

    // 4) Load the created object
    ESYS_TR objectHandle = ESYS_TR_NONE;
    rc = Esys_Load(
        esys,
        primaryHandle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        outPrivate,
        outPublic,
        &objectHandle
    );
    check_rc(rc, "Esys_Load");

    // 5) Make the object persistent at persistentHandle (requires owner auth)
    // EvictControl: hierarchy ESYS_TR_RH_OWNER, objectHandle -> persistentHandle
    rc = Esys_EvictControl(
        esys,
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
        Esys_FlushContext(esys, objectHandle);
        Esys_FlushContext(esys, primaryHandle);
        Esys_Free(outPrivate);
        Esys_Free(outPublic);
        Esys_Free(policyDigest);
        Esys_FlushContext(esys, sessionTrial);
        exit(1);
    }

    std::cout << "Sealed object made persistent at 0x" << std::hex << persistentHandle << std::dec << "\n";

    // 6) Cleanup: free created structures and flush contexts
    Esys_FlushContext(esys, objectHandle);
    Esys_FlushContext(esys, primaryHandle);
    Esys_Free(outPrivate);
    Esys_Free(outPublic);
    Esys_Free(policyDigest);
    Esys_FlushContext(esys, sessionTrial);
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

int setup()
{

    TPM2_HANDLE free_handle = find_free_handle();
    if (free_handle == 0) {
        std::cerr << "No free persistent handles available" << std::endl;
        return 1;
    }
    std::cout << "Found free persistent handle: 0x" << std::hex << free_handle << std::endl;

    auto newhandle = free_handle;

    
    // std::vector<uint8_t> secret = { 2,3,4,5,6 };
    // TPML_PCR_SELECTION pcrSelection;
    // memset(&pcrSelection, 0, sizeof(pcrSelection));
    // pcrSelection.count = 1;
    // pcrSelection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    // pcrSelection.pcrSelections[0].sizeofSelect = 3;
    // pcrSelection.pcrSelections[0].pcrSelect[0] = 0x04; // PCRs 0-2
    // pcrSelection.pcrSelections[0].pcrSelect[1] = 0x05;
    // pcrSelection.pcrSelections[0].pcrSelect[2] = 0x09;

    // std::vector<uint8_t> pcrDigestBytes = { /* your PCR digest bytes here */ };
    // seal_secret_to_persistent(g_esys_ctx, newhandle, secret, pcrSelection, pcrDigestBytes);

    // delete_persistent_handle(newhandle);

    return 0;
}

std::vector<uint8_t> retrieve_current_pcr_values(unsigned int pcr_mask) {
    std::vector<uint8_t> pcr_values;
    TPML_DIGEST *pcr_digest = nullptr;
    TPML_PCR_SELECTION pcr_selection;

    // Initialize PCR selection
    memset(&pcr_selection, 0, sizeof(pcr_selection));
    pcr_selection.count = 1;
    pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcr_selection.pcrSelections[0].sizeofSelect = 3;

    // Set PCR mask based on input
    for (int i = 0; i < 24; ++i) {
        if (pcr_mask & (1 << i)) {
            pcr_selection.pcrSelections[0].pcrSelect[i / 8] |= (1 << (i % 8));
        }
    }

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


std::vector<uint8_t> predicted_pcr_digest;
extern "C" void pcr_result_callback(const char *data,int len)
{
    for (int i = 0; i < len; ++i)
        predicted_pcr_digest.push_back(*data++);
}

int main(int argc, char* argv[])
{
    TSS2_RC rc;
    rc = Esys_Initialize(&g_esys_ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_Initialize failed: 0x" << std::hex << rc << std::endl;
        return 1;
    }


    char *args[]={"pcr-oracle","--from","eventlog","-F","luksury","4,5,9"};
    predicted_pcr_digest.clear();
    main_pcr_oracle(6, (args));

    auto current_pcr_digest = retrieve_current_pcr_values((1<<4)|(1<<5)|(1<<9));

    std::cout<<"size: " << predicted_pcr_digest.size() << " data:" << std::hex << std::setfill('0') << std::setw(2);
    for (auto byte : predicted_pcr_digest) {
        std::cout << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
    
    std::cout<<"size: " << current_pcr_digest.size() << " data:" << std::hex << std::setfill('0') << std::setw(2);
    for (auto byte : current_pcr_digest) {
        std::cout << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
    return 0;



    int ret = setup();

    Esys_Finalize(&g_esys_ctx);
    return ret;
}