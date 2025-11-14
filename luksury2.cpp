#include <iostream>
#include <cstring>
#include <vector>

#include <openssl/sha.h>  
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>


class TPM2PasswordSealer {
private:
    ESYS_CONTEXT *esys_ctx = nullptr;
    
    void cleanup() {
        if (esys_ctx) {
            Esys_Finalize(&esys_ctx);
        }
    }
    
    bool initializeContext() {
        TSS2_RC rc = Esys_Initialize(&esys_ctx, NULL, NULL);
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Failed to initialize ESYS context: " 
                      << Tss2_RC_Decode(rc) << std::endl;
            return false;
        }
        return true;
    }
    
public:
    ~TPM2PasswordSealer() {
        cleanup();
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

    
    bool sealPassword(const std::string &password, 
                     const uint32_t *pcrIndices, 
                     size_t numPcrs,
                     uint32_t persistentHandle) {
        
        if (!initializeContext()) {
            return false;
        }
        
        TSS2_RC rc;
        
        // Create PCR selection
        TPML_PCR_SELECTION pcrSelection = {};
        pcrSelection.count = 1;
        pcrSelection.pcrSelections[0].hash = TPM2_ALG_SHA256;
        pcrSelection.pcrSelections[0].sizeofSelect = 3;
        
        // Set the PCR bits
        for (size_t i = 0; i < numPcrs; i++) {
            uint32_t pcr = pcrIndices[i];
            pcrSelection.pcrSelections[0].pcrSelect[pcr / 8] |= (1 << (pcr % 8));
        }
        
        // Read current PCR values
        TPML_DIGEST *pcrValues = nullptr;
        TPML_PCR_SELECTION *pcrSelectionOut = nullptr;
        uint32_t pcrUpdateCounter;
        
        rc = Esys_PCR_Read(esys_ctx,
                          ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                          &pcrSelection,
                          &pcrUpdateCounter,
                          &pcrSelectionOut,
                          &pcrValues);

        std::vector<unsigned char> concateBuffer;
        std::cout << "PCR values read successfully. Count: " << pcrValues->count << std::endl;
        std::cout << "PCR values: \n";
        for (uint32_t i = 0; i < pcrValues->count; i++) {
            std::cout << "Bank " << i << ": ";
            for (size_t j = 0; j < pcrValues->digests[i].size; j++) {
                std::cout << std::hex << (int)pcrValues->digests[i].buffer[j];
            }
            std::cout << std::dec << std::endl;
            concateBuffer.insert(concateBuffer.end(), pcrValues->digests[i].buffer, pcrValues->digests[i].buffer + pcrValues->digests[i].size);
        };

        auto digest = concatenated_to_digest(concateBuffer);

        
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Failed to read PCR values: " 
                      << Tss2_RC_Decode(rc) << std::endl;
            return false;
        }
        
        // Create PCR policy
        ESYS_TR policySession;
        TPMT_SYM_DEF symmetric = {
            .algorithm = TPM2_ALG_NULL
        };
        
        rc = Esys_StartAuthSession(esys_ctx,
                                   ESYS_TR_NONE, ESYS_TR_NONE,
                                   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                   NULL,
                                   TPM2_SE_POLICY,
                                   &symmetric,
                                   TPM2_ALG_SHA256,
                                   &policySession);
        
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Failed to start auth session: " 
                      << Tss2_RC_Decode(rc) << std::endl;
            Esys_Free(pcrValues);
            Esys_Free(pcrSelectionOut);
            return false;
        }
        
        // Apply PCR policy
        rc = Esys_PolicyPCR(esys_ctx,
                           policySession,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           &digest,
                           &pcrSelection);
        
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Failed to set PCR policy: " 
                      << Tss2_RC_Decode(rc) << std::endl;
            Esys_FlushContext(esys_ctx, policySession);
            Esys_Free(pcrValues);
            Esys_Free(pcrSelectionOut);
            return false;
        }
        
        // Get policy digest
        TPM2B_DIGEST *policyDigest = nullptr;
        rc = Esys_PolicyGetDigest(esys_ctx,
                                 policySession,
                                 ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &policyDigest);
        
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Failed to get policy digest: " 
                      << Tss2_RC_Decode(rc) << std::endl;
            Esys_FlushContext(esys_ctx, policySession);
            Esys_Free(pcrValues);
            Esys_Free(pcrSelectionOut);
            return false;
        }
        
        // Prepare sensitive data (password)
        TPM2B_SENSITIVE_CREATE inSensitive = {};
        inSensitive.sensitive.data.size = std::min(password.size(), 
                                                   sizeof(inSensitive.sensitive.data.buffer));
        memcpy(inSensitive.sensitive.data.buffer, 
               password.c_str(), 
               inSensitive.sensitive.data.size);
        
        // Prepare public template
        TPM2B_PUBLIC inPublic = {};
        inPublic.size = 0;
        inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
        inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
        inPublic.publicArea.objectAttributes = (TPMA_OBJECT_FIXEDTPM |
                                                TPMA_OBJECT_FIXEDPARENT);
        inPublic.publicArea.authPolicy = *policyDigest;
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
        
        rc = Esys_CreatePrimary(esys_ctx,
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
            Esys_FlushContext(esys_ctx, policySession);
            Esys_Free(policyDigest);
            Esys_Free(pcrValues);
            Esys_Free(pcrSelectionOut);
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
        
        rc = Esys_Create(esys_ctx,
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
            Esys_FlushContext(esys_ctx, policySession);
            Esys_FlushContext(esys_ctx, srkHandle);
            Esys_Free(policyDigest);
            Esys_Free(pcrValues);
            Esys_Free(pcrSelectionOut);
            return false;
        }
        
        // Load the sealed object into TPM
        ESYS_TR loadedHandle;
        rc = Esys_Load(esys_ctx,
                      srkHandle,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      outPrivate,
                      outPublic,
                      &loadedHandle);
        
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Failed to load sealed object: " 
                      << Tss2_RC_Decode(rc) << std::endl;
            Esys_FlushContext(esys_ctx, policySession);
            Esys_FlushContext(esys_ctx, srkHandle);
            Esys_Free(outPrivate);
            Esys_Free(outPublic);
            Esys_Free(creationData);
            Esys_Free(creationHash);
            Esys_Free(creationTicket);
            Esys_Free(policyDigest);
            Esys_Free(pcrValues);
            Esys_Free(pcrSelectionOut);
            return false;
        }
        
        // Make the handle persistent
        ESYS_TR persistentHandleEsys;
        rc = Esys_EvictControl(esys_ctx,
                              ESYS_TR_RH_OWNER,
                              loadedHandle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              persistentHandle,
                              &persistentHandleEsys);
        
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Failed to make handle persistent: " 
                      << Tss2_RC_Decode(rc) << std::endl;
            Esys_FlushContext(esys_ctx, loadedHandle);
            Esys_FlushContext(esys_ctx, policySession);
            Esys_FlushContext(esys_ctx, srkHandle);
            Esys_Free(outPrivate);
            Esys_Free(outPublic);
            Esys_Free(creationData);
            Esys_Free(creationHash);
            Esys_Free(creationTicket);
            Esys_Free(policyDigest);
            Esys_Free(pcrValues);
            Esys_Free(pcrSelectionOut);
            return false;
        }
        
        std::cout << "Password successfully sealed with PCR values!" << std::endl;
        std::cout << "Persistent handle: 0x" << std::hex << persistentHandle << std::dec << std::endl;
        std::cout << "PCRs used: ";
        for (size_t i = 0; i < numPcrs; i++) {
            std::cout << pcrIndices[i] << " ";
        }
        std::cout << std::endl;
        
        // Cleanup
        Esys_FlushContext(esys_ctx, loadedHandle);
        Esys_FlushContext(esys_ctx, policySession);
        Esys_FlushContext(esys_ctx, srkHandle);
        Esys_Free(outPrivate);
        Esys_Free(outPublic);
        Esys_Free(creationData);
        Esys_Free(creationHash);
        Esys_Free(creationTicket);
        Esys_Free(policyDigest);
        Esys_Free(pcrValues);
        Esys_Free(pcrSelectionOut);
        
        return true;
    }
};

int main() {
    TPM2PasswordSealer sealer;
    
    // Example: Seal password with PCR 0, 1, and 7
    std::string password = "MySecretPassword123";
    uint32_t pcrs[] = {0, 1, 7};
    size_t numPcrs = sizeof(pcrs) / sizeof(pcrs[0]);
    
    if (sealer.sealPassword(password, pcrs, numPcrs, 0x81000002)) {
        std::cout << "Success!" << std::endl;
        return 0;
    } else {
        std::cerr << "Failed to seal password" << std::endl;
        return 1;
    }
}