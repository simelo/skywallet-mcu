
#include "fsm_sky_impl.h"

ErrCode_t msgSkycoinSignMessageImpl(SkycoinSignMessage* msg, ResponseSkycoinSignMessage* resp)
{
    // NOTE: twise the SKYCOIN_SIG_LEN because the hex format
    _Static_assert(sizeof(resp->signed_message) >= 2 * SKYCOIN_SIG_LEN,
                   "hex SKYCOIN_SIG_LEN do not fit in the response");
    CHECK_MNEMONIC_RET_ERR_CODE
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN] = {0};
    uint8_t seckey[SKYCOIN_SECKEY_LEN] = {0};
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    uint8_t signature[SKYCOIN_SIG_LEN];
    if (fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, msg->address_n) != ErrOk) {
        return ErrInvalidValue;
    }
    if (is_sha256_digest_hex(msg->message)) {
        writebuf_fromhexstr(msg->message, digest);
    } else {
        sha256sum((const uint8_t *)msg->message, digest, strlen(msg->message));
    }
    int res = skycoin_ecdsa_sign_digest(seckey, digest, signature);
    if (res == -2) {
        // Fail due to empty digest
        return ErrInvalidArg;
    } else if (res) {
        // Too many retries without a valid signature
        // -> fail with an error
        return ErrFailed;
    }
    const size_t hex_len = 2 * SKYCOIN_SIG_LEN;
    char signature_in_hex[hex_len];
    tohex(signature_in_hex, signature, SKYCOIN_SIG_LEN);
    memcpy(resp->signed_message, signature_in_hex, hex_len);
    return ErrOk;
}

ErrCode_t msgSignTransactionMessageImpl(uint8_t* message_digest, uint32_t index, char* signed_message)
{
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN] = {0};
    uint8_t seckey[SKYCOIN_SECKEY_LEN] = {0};
    uint8_t signature[SKYCOIN_SIG_LEN];
    ErrCode_t res = fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, index);
    if (res != ErrOk) {
        return res;
    }
    int signres = skycoin_ecdsa_sign_digest(seckey, message_digest, signature);
    if (signres == -2) {
        // Fail due to empty digest
        return ErrInvalidArg;
    } else if (res) {
        // Too many retries without a valid signature
        // -> fail with an error
        return ErrFailed;
    }
    tohex(signed_message, signature, SKYCOIN_SIG_LEN);
    #if EMULATOR
    printf("Size_sign: %d, sig(hex): %s\n", SKYCOIN_SIG_LEN * 2, signed_message);
    #endif
    return res;
}

ErrCode_t msgSkycoinAddressImpl(SkycoinAddress* msg, ResponseSkycoinAddress* resp)
{
    uint8_t seckey[32] = {0};
    uint8_t pubkey[33] = {0};
    uint32_t start_index = !msg->has_start_index ? 0 : msg->start_index;
    CHECK_PIN_RET_ERR_CODE
    if (msg->address_n > 99) {
        return ErrTooManyAddresses;
    }

    CHECK_MNEMONIC_RET_ERR_CODE

    if (fsm_getKeyPairAtIndex(msg->address_n, pubkey, seckey, resp, start_index) != ErrOk) {
        return ErrAddressGeneration;
    }
    if (msg->address_n == 1 && msg->has_confirm_address && msg->confirm_address) {
        return ErrUserConfirmation;
    }
    return ErrOk;
}

ErrCode_t msgSkycoinCheckMessageSignatureImpl(SkycoinCheckMessageSignature* msg, Success* successResp, Failure* failureResp)
{
    // NOTE(): -1 because the end of string ('\0')
    // /2 because the hex to buff conversion.
    _Static_assert((sizeof(msg->message) - 1) / 2 == SHA256_DIGEST_LENGTH,
                   "Invalid buffer size for message");
    _Static_assert((sizeof(msg->signature) - 1) / 2 == SKYCOIN_SIG_LEN,
                    "Invalid buffer size for signature");
    uint8_t sig[SKYCOIN_SIG_LEN] = {0};
    // NOTE(): -1 because the end of string ('\0')
    char address[sizeof(msg->address) - 1];
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN] = {0};
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    if (is_sha256_digest_hex(msg->message)) {
        tobuff(msg->message, digest, MIN(sizeof(digest), sizeof(msg->message)));
    } else {
        sha256sum((const uint8_t *)msg->message, digest, strlen(msg->message));
    }
    tobuff(msg->signature, sig, sizeof(sig));
    ErrCode_t ret = (skycoin_ecdsa_verify_digest_recover(sig, digest, pubkey) == 0) ? ErrOk : ErrInvalidSignature;
    if (ret != ErrOk) {
        strncpy(failureResp->message, _("Address recovery failed"), sizeof(failureResp->message));
        failureResp->has_message = true;
        return ErrInvalidSignature;
    }
    if (!verify_pub_key(pubkey)) {
        strncpy(failureResp->message, _("Can not verify pub key"), sizeof(failureResp->message));
        failureResp->has_message = true;
        return ErrAddressGeneration;
    }
    size_t address_size = sizeof(address);
    if (!skycoin_address_from_pubkey(pubkey, address, &address_size)) {
        strncpy(failureResp->message, _("Can not verify pub key"), sizeof(failureResp->message));
        failureResp->has_message = true;
        return ErrAddressGeneration;
    }
    if (memcmp(address, msg->address, address_size)) {
        strncpy(failureResp->message, _("Address does not match"), sizeof(failureResp->message));
        failureResp->has_message = true;
        return ErrInvalidSignature;
    }
    memcpy(successResp->message, address, address_size);
    successResp->has_message = true;
    return ErrOk;
}

ErrCode_t msgTransactionSignImpl(TransactionSign* msg, ErrCode_t (*funcConfirmTxn)(char*, char*, TransactionSign*, uint32_t), ResponseTransactionSign* resp)
{
    if (msg->nbIn > sizeof(msg->transactionIn)/sizeof(*msg->transactionIn)) {
        return ErrInvalidArg;
    }
    if (msg->nbOut > sizeof(msg->transactionOut)/sizeof(*msg->transactionOut)) {
        return ErrInvalidArg;
    }
    #if EMULATOR
    printf("%s: %d. nbOut: %d\n",
        _("Transaction signed nbIn"),
        msg->nbIn, msg->nbOut);

    for (uint32_t i = 0; i < msg->nbIn; ++i) {
        printf("Input: addressIn: %s, index: %d\n",
            msg->transactionIn[i].hashIn, msg->transactionIn[i].index);
    }
    for (uint32_t i = 0; i < msg->nbOut; ++i) {
        printf("Output: coin: %" PRIu64 ", hour: %" PRIu64 " address: %s address_index: %d\n",
            msg->transactionOut[i].coin, msg->transactionOut[i].hour,
            msg->transactionOut[i].address, msg->transactionOut[i].address_index);
    }
    #endif
    Transaction transaction;
    transaction_initZeroTransaction(&transaction);
    for (uint32_t i = 0; i < msg->nbIn; ++i) {
        uint8_t hashIn[32];
        writebuf_fromhexstr(msg->transactionIn[i].hashIn, hashIn);
        transaction_addInput(&transaction, hashIn);
    }
    for (uint32_t i = 0; i < msg->nbOut; ++i) {
        char strHour[30];
        char strCoin[30];
        char strValue[20];
        char* coinString = msg->transactionOut[i].coin == 1000000 ? _("coin") : _("coins");
        char* hourString = (msg->transactionOut[i].hour == 1 || msg->transactionOut[i].hour == 0) ? _("hour") : _("hours");
        char* strValueMsg = sprint_coins(msg->transactionOut[i].coin, SKYPARAM_DROPLET_PRECISION_EXP, sizeof(strValue), strValue);
        if (strValueMsg == NULL) {
            // FIXME: For Skycoin coin supply and precision buffer size should be enough
            strcpy(strCoin, "too many coins");
        }
        sprintf(strCoin, "%s %s %s", _("send"), strValueMsg, coinString);
        sprintf(strHour, "%" PRIu64 " %s", msg->transactionOut[i].hour, hourString);

        if (msg->transactionOut[i].has_address_index) {
            uint8_t pubkey[33] = {0};
            uint8_t seckey[32] = {0};
            size_t size_address = 36;
            char address[36] = {0};
            ErrCode_t ret = fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, msg->transactionOut[i].address_index);
            if (ret != ErrOk) {
                return ret;
            }
            if (!skycoin_address_from_pubkey(pubkey, address, &size_address)) {
                return ErrAddressGeneration;
            }
            if (strcmp(msg->transactionOut[i].address, address) != 0) {
                // fsm_sendFailure(FailureType_Failure_AddressGeneration, _("Wrong return address"));
                #if EMULATOR
                printf("Internal address: %s, message address: %s\n", address, msg->transactionOut[i].address);
                printf("Comparaison size %ld\n", size_address);
                #endif
                return ErrAddressGeneration;
            }
        } else {
            // NOTICE: A single output per address is assumed
            ErrCode_t err = funcConfirmTxn(strCoin, strHour, msg, i);
            if (err != ErrOk)
                return err;
        }
        transaction_addOutput(&transaction, msg->transactionOut[i].coin, msg->transactionOut[i].hour, msg->transactionOut[i].address);
    }

    CHECK_PIN_UNCACHED_RET_ERR_CODE

    for (uint32_t i = 0; i < msg->nbIn; ++i) {
        uint8_t digest[32] = {0};
        transaction_msgToSign(&transaction, i, digest);
        // Only sign inputs owned by Skywallet device
        if (msg->transactionIn[i].has_index) {
            if (msgSignTransactionMessageImpl(digest, msg->transactionIn[i].index, resp->signatures[resp->signatures_count]) != ErrOk) {
                //fsm_sendFailure(FailureType_Failure_InvalidSignature, NULL);
                //layoutHome();
                return ErrInvalidSignature;
            }
        } else {
            // Null sig
            uint8_t signature[65];
            memset(signature, 0, sizeof(signature));
            tohex(resp->signatures[resp->signatures_count], signature, sizeof(signature));
        }
        resp->signatures_count++;
        #if EMULATOR
        char str[64];
        tohex(str, (uint8_t*)digest, 32);
        printf("Signing message:  %s\n", str);
        printf("Signed message:  %s\n", resp->signatures[i]);
        printf("Nb signatures: %d\n", resp->signatures_count);
        #endif
    }
    if (resp->signatures_count != msg->nbIn) {
        // Ensure number of sigs and inputs is the same. Mismatch should never happen.
        return ErrFailed;
    }
    #if EMULATOR
    char str[64];
    tohex(str, transaction.innerHash, 32);
    printf("InnerHash %s\n", str);
    printf("Signed message:  %s\n", resp->signatures[0]);
    printf("Nb signatures: %d\n", resp->signatures_count);
    #endif
    //layoutHome();
    return ErrOk;
}

ErrCode_t msgSignTxImpl(SignTx *msg, TxRequest *resp) {
    #if EMULATOR
    printf("%s: %d. nbOut: %d\n",
        _("Transaction signed nbIn"),
        msg->inputs_count, msg->outputs_count);
    #endif
    TxSignContext *context = TxSignCtx_Get();
    if(context->state != Destroyed) {
        TxSignCtx_Destroy(context);
        return ErrFailed;
    }
    // Init TxSignContext
    context = TxSignCtx_Init();
    if (context->mnemonic_change){
        TxSignCtx_Destroy(context);
        return ErrFailed;
    }
    memcpy(context->coin_name, msg->coin_name, 36 * sizeof(char));
    context->state = InnerHashInputs;
    context->current_nbIn = 0;
    context->current_nbOut = 0;
    context->lock_time = msg->lock_time;
    context->nbIn = msg->inputs_count;
    context->nbOut = msg->outputs_count;
    sha256_Init(&context->sha256_ctx);
    memcpy(context->tx_hash, msg->tx_hash, 65 * sizeof(char));
    context->version = msg->version;
    context->has_innerHash = false;
    context->requestIndex = 1;

    // Init Inputs head on sha256
    TxSignCtx_AddSizePrefix(context,msg->inputs_count);

    // Build response TxRequest
    resp->has_details = true;
    resp->details.has_request_index = true;
    resp->details.request_index = 1;
    memcpy(resp->details.tx_hash, msg->tx_hash, 65 * sizeof(char));
    resp->request_type = TxRequest_RequestType_TXINPUT;
    return ErrOk;
}

ErrCode_t reqConfirmTransaction(uint64_t coins, uint64_t hours,char* address){
    char strCoins[32];
    char strHours[32];
    char strValue[20];
    char* coinString = coins == 1000000 ? _("coin") : _("coins");
    char* hourString = (hours == 1 || hours == 0) ? _("hour") : _("hours");
    char* strValueMsg = sprint_coins(coins,SKYPARAM_DROPLET_PRECISION_EXP, sizeof(strValue), strValue);
    sprintf(strCoins, "%s %s %s", _("send"), strValueMsg, coinString);
    sprintf(strHours, "%" PRIu64 "%s", hours, hourString);
    layoutDialogSwipe(&bmp_icon_question,_("Cancel"),_("Next"),NULL,_("Do you really want to"),strCoins,strHours,_("to address"), _("..."), NULL);
    CHECK_BUTTON_PROTECT_RET_ERR_CODE
    layoutAddress(address);
    CHECK_BUTTON_PROTECT_RET_ERR_CODE
    return ErrOk;
}

ErrCode_t msgTxAckImpl(TxAck *msg, TxRequest *resp) {
    TxSignContext *ctx = TxSignCtx_Get();
    if (ctx->state != Start && ctx->state != InnerHashInputs && ctx->state != InnerHashOutputs && ctx->state != Signature) {
        TxSignCtx_Destroy(ctx);
        return ErrInvalidArg;
    }
    #if EMULATOR
    switch (ctx->state) {
        case InnerHashInputs:
            printf("-> Inner Hash inputs\n");
            break;
        case InnerHashOutputs:
            printf("-> Inner Hash outputs\n");
            break;
        case Signature:
            printf("-> Signatures\n");
            break;
        default:
            printf("-> Unexpected\n");
            break;
    }
    for(uint32_t i = 0; i < msg->tx.inputs_count; ++i) {
        printf("   %d - Input: addressIn: %s, address_n: ", i + 1,
            msg->tx.inputs[i].hashIn);
        if (msg->tx.inputs[i].address_n_count != 0)
            printf("%d",msg->tx.inputs[i].address_n[0]);
        printf("\n");
    }
    for (uint32_t i = 0; i < msg->tx.outputs_count; ++i) {
        printf("   %d - Output: coins: %" PRIu64 ", hours: %" PRIu64 " address: %s address_n: ", i + 1, msg->tx.outputs[i].coins, msg->tx.outputs[i].hours, msg->tx.outputs[i].address);
        if (msg->tx.outputs[i].address_n_count != 0) {
            printf("%d",msg->tx.outputs[i].address_n[0]);
        }
        printf("\n");
    }
    #endif
    if (ctx->mnemonic_change){
        TxSignCtx_Destroy(ctx);
        return ErrFailed;
    }
    uint8_t inputs[7][32];
    for (uint8_t i = 0; i < msg->tx.inputs_count; ++i) {
        writebuf_fromhexstr(msg->tx.inputs[i].hashIn, inputs[i]);
    }
    switch (ctx->state) {
        case InnerHashInputs:
            if (!msg->tx.inputs_count || msg->tx.outputs_count) {
                TxSignCtx_Destroy(ctx);
                return ErrInvalidArg;
            }
            TxSignCtx_UpdateInputs(ctx, inputs, msg->tx.inputs_count);
            if (ctx->current_nbIn != ctx->nbIn)
                resp->request_type = TxRequest_RequestType_TXINPUT;
            else {
                TxSignCtx_AddSizePrefix(ctx,ctx->nbOut);
                resp->request_type = TxRequest_RequestType_TXOUTPUT;
                ctx->state = InnerHashOutputs;
            }
            break;
        case InnerHashOutputs:
            if (!msg->tx.outputs_count || msg->tx.inputs_count) {
                TxSignCtx_Destroy(ctx);
                return ErrInvalidArg;
            }
            TransactionOutput outputs[7];
            for (uint8_t i = 0; i < msg->tx.outputs_count; ++i) {
                #if !EMULATOR
                if(!msg->tx.outputs[i].address_n_count){
                    ErrCode_t err = reqConfirmTransaction(msg->tx.outputs[i].coins,msg->tx.outputs[i].hours,msg->tx.outputs[i].address);
                    if (err != ErrOk)
                        return err;
                }
                #endif
                outputs[i].coin = msg->tx.outputs[i].coins;
                outputs[i].hour = msg->tx.outputs[i].hours;
                size_t len = 36;
                uint8_t b58string[36];
                b58tobin(b58string, &len, msg->tx.outputs[i].address);
                memcpy(outputs[i].address, &b58string[36 - len], len);
            }
            TxSignCtx_UpdateOutputs(ctx,outputs, msg->tx.outputs_count);
            if (ctx->current_nbOut != ctx->nbOut) {
                resp->request_type = TxRequest_RequestType_TXOUTPUT;
            } else {
                TxSignCtx_finishInnerHash(ctx);
                ctx->state = Signature;
                ctx->current_nbIn = 0;
                resp->request_type = TxRequest_RequestType_TXINPUT;
            }
            break;
        case Signature:
            if (!msg->tx.inputs_count || msg->tx.outputs_count) {
                TxSignCtx_Destroy(ctx);
                return ErrInvalidArg;
            }
            if (!ctx->has_innerHash) {
                TxSignCtx_Destroy(ctx);
                return ErrFailed;
            }
            uint8_t signCount = 0;
            for (uint8_t i = 0; i < msg->tx.inputs_count; ++i) {
                if (msg->tx.inputs[i].address_n_count) {
                    uint8_t shaInput[64];
                    uint8_t msg_digest[32] = {0};
                    memcpy(shaInput, ctx->innerHash, 32);
                    memcpy(&shaInput[32], &inputs[i], 32);
                    SHA256_CTX sha256ctx;
                    sha256_Init(&sha256ctx);
                    sha256_Update(&sha256ctx, shaInput, 64);
                    sha256_Final(&sha256ctx, msg_digest);
                    resp->sign_result[signCount].has_signature = true;
                    msgSignTransactionMessageImpl(msg_digest,msg->tx.inputs[i].address_n[0],resp->sign_result[signCount].signature);
                    resp->sign_result[signCount].has_signature_index = true;
                    resp->sign_result[signCount].signature_index = i;
                    signCount++;
                }
                ctx->current_nbIn++;
            }
            resp->sign_result_count = signCount;
            if (ctx->current_nbIn != ctx->nbIn)
                resp->request_type = TxRequest_RequestType_TXINPUT;
            else{
                resp->request_type = TxRequest_RequestType_TXFINISHED;
            }
            break;
        default:
            break;
    }
    resp->has_details = true;
    resp->details.has_request_index = true;
    ctx->requestIndex++;
    resp->details.request_index = ctx->requestIndex;
    resp->details.has_tx_hash = true;
    memcpy(resp->details.tx_hash, ctx->tx_hash, strlen(ctx->tx_hash) * sizeof(char));
    if (resp->request_type == TxRequest_RequestType_TXFINISHED)
        TxSignCtx_Destroy(ctx);
    return ErrOk;
}
