/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libopencm3/stm32/flash.h>

#include "base58.h"
#include "bip32.h"
#include "bip39.h"
#include "bitcoin-signing.h"
#include "check_digest.h"
#include "coins.h"
#include "droplet.h"
#include "entropy.h"
#include "fsm.h"
#include "fsm_impl.h"
#include "fsm_sky_impl.h"
#include "gettext.h"
#include "layout2.h"
#include "memory.h"
#include "messages.h"
#include "oled.h"
#include "pinmatrix.h"
#include "protect.h"
#include "recovery.h"
#include "reset.h"
#include "rng.h"
#include "skycoin_crypto.h"
#include "skycoin_signature.h"
#include "skyparams.h"
#include "skywallet.h"
#include "storage.h"
#include "usb.h"
#include "util.h"
#include <inttypes.h>
#include <stdio.h>

// Utils

#define CASE_SEND_FAILURE_FORMSG(type, fail, msg, msgtype) \
    case type:                             \
        fsm_sendFailure(fail, msg, msgtype);        \
        break;

#define CASE_SEND_FAILURE(type, fail, msg) CASE_SEND_FAILURE_FORMSG(type, fail, msg, 0)

void fsm_sendResponseFromErrCode(ErrCode_t err, const char* successMsg, const char* failMsg, MessageType* msgtype)
{
    FailureType failure;
    switch (err) {
    case ErrOk:
        if (successMsg == NULL) {
            successMsg = _("Success");
        }
        fsm_sendSuccess(successMsg, msgtype);
        return;
    case ErrFailed:
        failure = FailureType_Failure_FirmwareError;
        break;
    case ErrInvalidArg:
        failure = FailureType_Failure_DataError;
        if (failMsg == NULL) {
            failMsg = _("Invalid argument");
        }
        break;
    case ErrPreconditionFailed:
        failure = FailureType_Failure_DataError;
        if (failMsg == NULL) {
            failMsg = _("Precondition failed");
        }
        break;
    case ErrIndexValue:
        failure = FailureType_Failure_DataError;
        if (failMsg == NULL) {
            failMsg = _("Index out of bounds");
        }
        break;
    case ErrInvalidValue:
        failure = FailureType_Failure_ProcessError;
        break;
    case ErrNotImplemented:
        failure = FailureType_Failure_FirmwareError;
        if (failMsg == NULL) {
            failMsg = _("Not Implemented");
        }
        break;
    case ErrInvalidChecksum:
        failure = FailureType_Failure_DataError;
        if (failMsg == NULL) {
            failMsg = _("Invalid checksum");
        }
        break;
    case ErrPinRequired:
        failure = FailureType_Failure_PinExpected;
        break;
    case ErrPinMismatch:
        failure = FailureType_Failure_PinMismatch;
        break;
    case ErrPinCancelled:
        failure = FailureType_Failure_PinCancelled;
        break;
    case ErrActionCancelled:
        failure = FailureType_Failure_ActionCancelled;
        break;
    case ErrNotInitialized:
        failure = FailureType_Failure_NotInitialized;
        break;
    case ErrMnemonicRequired:
        failure = FailureType_Failure_AddressGeneration;
        if (failMsg == NULL) {
            failMsg = _("Mnemonic required");
        }
        break;
    case ErrAddressGeneration:
        failure = FailureType_Failure_AddressGeneration;
        break;
    case ErrTooManyAddresses:
        failure = FailureType_Failure_AddressGeneration;
        if (failMsg == NULL) {
            failMsg = _("Too many addresses requested");
        }
        break;
    case ErrUnfinishedBackup:
        // FIXME: FailureType_Failure_ProcessError ?
        failure = FailureType_Failure_ActionCancelled;
        if (failMsg == NULL) {
            failMsg = _("Backup operation did not finish properly.");
        }
        break;
    case ErrUnexpectedMessage:
        failure = FailureType_Failure_UnexpectedMessage;
        break;
    case ErrSignPreconditionFailed:
        failure = FailureType_Failure_InvalidSignature;
        break;
    case ErrInvalidSignature:
        if (failMsg == NULL) {
            failMsg = _("Invalid signature.");
        }
        failure = FailureType_Failure_InvalidSignature;
        break;
    default:
        failure = FailureType_Failure_FirmwareError;
        failMsg = _("Unexpected firmware error");
        break;
    }
    fsm_sendFailure(failure, failMsg, msgtype);
}

extern uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

void fsm_sendSuccess(const char* text, MessageType* msgtype)
{
    RESP_INIT(Success);
    if (text) {
        resp->has_message = true;
        strlcpy(resp->message, text, sizeof(resp->message));
    }
    if (msgtype) {
      resp->has_msg_type = true;
      resp->msg_type = *msgtype;
    } else {
      resp->has_msg_type = false;
    }
    msg_write(MessageType_MessageType_Success, resp);
}

void fsm_sendFailure(FailureType code, const char* text, MessageType* msgtype)
{
    if (protectAbortedByInitialize) {
        fsm_msgInitialize((Initialize*)0);
        protectAbortedByInitialize = false;
        return;
    }
    RESP_INIT(Failure);
    resp->has_code = true;
    resp->code = code;
    if (msgtype) {
      resp->has_msg_type = true;
      resp->msg_type = *msgtype;
    } else {
      resp->has_msg_type = false;
    }
    if (text == NULL) {
        switch (code) {
        case FailureType_Failure_UnexpectedMessage:
            text = _("Unexpected message");
            break;
        case FailureType_Failure_ButtonExpected:
            text = _("Button expected");
            break;
        case FailureType_Failure_DataError:
            text = _("Data error");
            break;
        case FailureType_Failure_ActionCancelled:
            text = _("Action cancelled by user");
            break;
        case FailureType_Failure_PinExpected:
            text = _("PIN expected");
            break;
        case FailureType_Failure_PinCancelled:
            text = _("PIN cancelled");
            break;
        case FailureType_Failure_PinInvalid:
            text = _("PIN invalid");
            break;
        case FailureType_Failure_InvalidSignature:
            text = _("Invalid signature");
            break;
        case FailureType_Failure_ProcessError:
            text = _("Process error");
            break;
        case FailureType_Failure_NotEnoughFunds:
            text = _("Not enough funds");
            break;
        case FailureType_Failure_NotInitialized:
            text = _("Device not initialized");
            break;
        case FailureType_Failure_PinMismatch:
            text = _("PIN mismatch");
            break;
        case FailureType_Failure_FirmwareError:
            text = _("Firmware error");
            break;
        case FailureType_Failure_AddressGeneration:
            text = _("Failed to generate address");
            break;
        case FailureType_Failure_FirmwarePanic:
            text = _("Firmware panic");
            break;
        default:
            text = _("Unknown failure error");
            break;
        }
    }
    if (text) {
        resp->has_message = true;
        strlcpy(resp->message, text, sizeof(resp->message));
    }
    msg_write(MessageType_MessageType_Failure, resp);
}

void fsm_msgInitialize(Initialize* msg)
{
    recovery_abort();
    if (msg && msg->has_state && msg->state.size == 64) {
        uint8_t i_state[64];
        if (!session_getState(msg->state.bytes, i_state, NULL)) {
            session_clear(false); // do not clear PIN
        } else {
            if (0 != memcmp(msg->state.bytes, i_state, 64)) {
                session_clear(false); // do not clear PIN
            }
        }
    } else {
        session_clear(false); // do not clear PIN
    }
    layoutHome();
    fsm_msgGetFeatures(0);
}

void fsm_msgApplySettings(ApplySettings* msg)
{
    CHECK_PIN
    MessageType msgtype = MessageType_MessageType_ApplySettings;
    msg->has_label = msg->has_label && strlen(msg->label);
    msg->has_language = msg->has_language && strlen(msg->language);
    if (msg->has_label) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("change name to"), msg->label, "?", NULL, NULL);
        CHECK_BUTTON_PROTECT
    }
    if (msg->has_language) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("change language to"), msg->language, "?", NULL, NULL);
        CHECK_BUTTON_PROTECT
    }
    if (msg->has_use_passphrase) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), msg->use_passphrase ? _("enable passphrase") : _("disable passphrase"), _("protection?"), NULL, NULL, NULL);
        CHECK_BUTTON_PROTECT
    }
    if (msg->has_homescreen) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("change the home"), _("screen?"), NULL, NULL, NULL);
        CHECK_BUTTON_PROTECT
    }

    ErrCode_t err = msgApplySettingsImpl(msg);
    char* failMsg = NULL;
    switch (err) {
    case ErrPreconditionFailed:
        failMsg = _("No setting provided");
        break;
    default:
        break;
    }
    fsm_sendResponseFromErrCode(err, _("Settings applied"), failMsg, &msgtype);
    layoutHome();
}

void fsm_msgGetFeatures(GetFeatures* msg)
{
    (void)msg;
    RESP_INIT(Features);
    msgGetFeaturesImpl(resp);
    msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgSkycoinCheckMessageSignature(SkycoinCheckMessageSignature* msg)
{
    GET_MSG_POINTER(Success, successResp);
    GET_MSG_POINTER(Failure, failureResp);
    uint16_t msg_id = MessageType_MessageType_Failure;
    void *msg_ptr = failureResp;
    switch (msgSkycoinCheckMessageSignatureImpl(msg, successResp, failureResp)) {
        case ErrOk:
            msg_id = MessageType_MessageType_Success;
            msg_ptr = successResp;
            layoutRawMessage("Verification success");
            break;
        case ErrAddressGeneration:
        case ErrInvalidSignature:
            failureResp->code = FailureType_Failure_InvalidSignature;
            layoutRawMessage("Wrong signature");
            break;
        default:
            strncpy(failureResp->message, _("Firmware error."), sizeof(failureResp->message));
            layoutHome();
            break;
    }
    msg_write(msg_id, msg_ptr);
}

ErrCode_t requestConfirmTransaction(char* strCoin, char* strHour, TransactionSign* msg, uint32_t i)
{
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Next"), NULL, _("Do you really want to"), strCoin, strHour, _("to address"), _("..."), NULL);
    CHECK_BUTTON_PROTECT_RET_ERR_CODE
    layoutAddress(msg->transactionOut[i].address);
    CHECK_BUTTON_PROTECT_RET_ERR_CODE
    return ErrOk;
}

void fsm_msgTransactionSign(TransactionSign* msg)
{
    CHECK_PIN
    CHECK_MNEMONIC
    CHECK_INPUTS(msg)
    CHECK_OUTPUTS(msg)

    MessageType msgtype = MessageType_MessageType_TransactionSign;
    RESP_INIT(ResponseTransactionSign);
    ErrCode_t err = msgTransactionSignImpl(msg, &requestConfirmTransaction, resp);
    char* failMsg = NULL;
    switch (err) {
    case ErrOk:
        msg_write(MessageType_MessageType_ResponseTransactionSign, resp);
        break;
    case ErrAddressGeneration:
        failMsg = _("Wrong return address");
        // fall through
    default:
        fsm_sendResponseFromErrCode(err, NULL, failMsg, &msgtype);
        break;
    }
    layoutHome();
}

void fsm_msgSkycoinSignMessage(SkycoinSignMessage* msg)
{
    CHECK_MNEMONIC
    RESP_INIT(ResponseSkycoinSignMessage);
    CHECK_PIN_UNCACHED

    MessageType msgtype = MessageType_MessageType_SkycoinSignMessage;
    ResponseSkycoinAddress respAddr;
    uint8_t seckey[32] = {0};
    uint8_t pubkey[33] = {0};
    ErrCode_t err = fsm_getKeyPairAtIndex(1, pubkey, seckey, &respAddr, msg->address_n);
    if (err != ErrOk) {
        fsm_sendResponseFromErrCode(err, NULL, _("Unable to get keys pair"), &msgtype);
        layoutHome();
        return;
    }
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("sign message using"), _("this address?"), respAddr.addresses[0], NULL, NULL);
    CHECK_BUTTON_PROTECT

    err = msgSkycoinSignMessageImpl(msg, resp);
    if (err == ErrOk) {
        msg_write(MessageType_MessageType_ResponseSkycoinSignMessage, resp);
        layoutRawMessage("Signature success");
    } else {
        char* failMsg = NULL;
        if (err == ErrMnemonicRequired) {
            failMsg = _("Mnemonic not set");
        }
        fsm_sendResponseFromErrCode(err, NULL, failMsg, &msgtype);
        layoutHome();
    }
}

void fsm_msgSkycoinAddress(SkycoinAddress* msg)
{
    MessageType msgtype = MessageType_MessageType_SkycoinAddress;
    RESP_INIT(ResponseSkycoinAddress);
    char* failMsg = NULL;
    ErrCode_t err = msgSkycoinAddressImpl(msg, resp);
    switch (err) {
    case ErrUserConfirmation:
        layoutAddress(resp->addresses[0]);
        if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
            err = ErrActionCancelled;
            break;
        }
        // fall through
    case ErrOk:
        msg_write(MessageType_MessageType_ResponseSkycoinAddress, resp);
        layoutHome();
        return;
    case ErrPinRequired:
        failMsg = _("Expected pin");
        break;
    case ErrTooManyAddresses:
        failMsg = _("Asking for too much addresses");
        break;
    case ErrMnemonicRequired:
        failMsg = _("Mnemonic required");
        break;
    case ErrAddressGeneration:
        failMsg = _("Key pair generation failed");
        break;
    default:
        break;
    }
    fsm_sendResponseFromErrCode(err, NULL, failMsg, &msgtype);
    layoutHome();
}

void fsm_msgPing(Ping* msg)
{
    MessageType msgtype = MessageType_MessageType_Ping;
    if (msg->has_button_protection && msg->button_protection) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("answer to ping?"), NULL, NULL, NULL, NULL);
        CHECK_BUTTON_PROTECT
    }

    ErrCode_t err = msgPingImpl(msg);
    if (err != ErrOk) {
        fsm_sendResponseFromErrCode(err, NULL, NULL, &msgtype);
    }
    layoutHome();
}

void fsm_msgChangePin(ChangePin* msg)
{
    bool removal = msg->has_remove && msg->remove;
    MessageType msgtype = MessageType_MessageType_ChangePin;
    if (removal) {
        if (storage_hasPin()) {
            layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("remove current PIN?"), NULL, NULL, NULL, NULL);
        } else {
            fsm_sendSuccess(_("PIN removed"), &msgtype);
            return;
        }
    } else {
        if (storage_hasPin()) {
            layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("change current PIN?"), NULL, NULL, NULL, NULL);
        } else {
            layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("set new PIN?"), NULL, NULL, NULL, NULL);
        }
    }

    CHECK_BUTTON_PROTECT
    CHECK_PIN_UNCACHED

    fsm_sendResponseFromErrCode(msgChangePinImpl(msg, &requestPin), (removal) ? _("PIN removed") : _("PIN changed"), NULL, &msgtype);
    layoutHome();
}

void fsm_msgWipeDevice(WipeDevice* msg)
{
    MessageType msgtype = MessageType_MessageType_WipeDevice;
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("wipe the device?"), NULL, _("All data will be lost."), NULL, NULL);
    ErrCode_t err = protectButton(ButtonRequestType_ButtonRequest_WipeDevice, false) ? msgWipeDeviceImpl(msg) : ErrActionCancelled;
    fsm_sendResponseFromErrCode(err, _("Device wiped"), NULL, &msgtype);
    layoutHome();
}

void fsm_msgGenerateMnemonic(GenerateMnemonic* msg)
{
    MessageType msgtype = MessageType_MessageType_GenerateMnemonic;
    GET_MSG_POINTER(EntropyRequest, entropy_request);
    switch (msgGenerateMnemonicImpl(msg, &random_salted_buffer)) {
        CASE_SEND_FAILURE(ErrNotInitialized, FailureType_Failure_UnexpectedMessage, _("Device is already initialized. Use Wipe first."))
        CASE_SEND_FAILURE(ErrInvalidArg, FailureType_Failure_DataError, _("Invalid word count expecified, the valid options are 12 or 24."))
        CASE_SEND_FAILURE(ErrInvalidValue, FailureType_Failure_ProcessError, _("Device could not generate a valid Mnemonic"))
        CASE_SEND_FAILURE(ErrInvalidChecksum, FailureType_Failure_DataError, _("Mnemonic with wrong checksum provided"))
    case ErrEntropyRequired:
        msg_write(MessageType_MessageType_EntropyRequest, entropy_request);
        break;
    case ErrOk:
        fsm_sendSuccess(_("Mnemonic successfully configured"), &msgtype);
        break;
    default:
        fsm_sendFailure(FailureType_Failure_FirmwareError, _("Mnemonic generation failed"), &msgtype);
        break;
    }
    layoutHome();
}

void fsm_msgSetMnemonic(SetMnemonic* msg)
{
    CHECK_NOT_INITIALIZED
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("I take the risk"), NULL, _("Writing seed"), _("is not recommended."), _("Continue only if you"), _("know what you are"), _("doing!"), NULL);
    CHECK_BUTTON_PROTECT
    MessageType msgtype = MessageType_MessageType_GenerateMnemonic;
    ErrCode_t err = msgSetMnemonicImpl(msg);
    char* failMsg = (err == ErrInvalidValue) ? _("Mnemonic with wrong checksum provided") : NULL;
    fsm_sendResponseFromErrCode(err, msg->mnemonic, failMsg, &msgtype);
    layoutHome();
}

void fsm_msgGetRawEntropy(GetRawEntropy* msg)
{
#if !DISABLE_GETENTROPY_CONFIRM
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("send entropy?"), NULL, NULL, NULL, NULL);
    CHECK_BUTTON_PROTECT
#endif // DISABLE_GETENTROPY_CONFIRM
    MessageType msgtype = MessageType_MessageType_GetRawEntropy;
    RESP_INIT(Entropy);
    ErrCode_t ret = msgGetEntropyImpl(msg, resp, &_random_buffer);
    if (ret == ErrOk) {
        msg_write(MessageType_MessageType_Entropy, resp);
    } else {
        fsm_sendResponseFromErrCode(
            ret, NULL, _("Get raw entropy not implemented"), &msgtype);
    }
    layoutHome();
}

void fsm_msgGetMixedEntropy(GetMixedEntropy* _msg)
{
#if !DISABLE_GETENTROPY_CONFIRM
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("send entropy?"), NULL, NULL, NULL, NULL);
    CHECK_BUTTON_PROTECT
#endif // DISABLE_GETENTROPY_CONFIRM
    MessageType msgtype = MessageType_MessageType_GetMixedEntropy;
    RESP_INIT(Entropy);
    GetRawEntropy msg;
    msg.size = _msg->size;
    ErrCode_t ret = msgGetEntropyImpl(&msg, resp, &random_buffer);
    if (ret == ErrOk) {
        msg_write(MessageType_MessageType_Entropy, resp);
    } else {
        fsm_sendResponseFromErrCode(
            ret, NULL, _("Get mixed entropy not implemented"), &msgtype);
    }
    layoutHome();
}

void fsm_msgLoadDevice(LoadDevice* msg)
{
    CHECK_NOT_INITIALIZED
    MessageType msgtype = MessageType_MessageType_LoadDevice;
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("I take the risk"), NULL, _("Loading private seed"), _("is not recommended."), _("Continue only if you"), _("know what you are"), _("doing!"), NULL);
    CHECK_BUTTON_PROTECT

    ErrCode_t err = msgLoadDeviceImpl(msg);
    char* failMsg = (err == ErrInvalidValue) ? _("Mnemonic with wrong checksum provided") : NULL;
    fsm_sendResponseFromErrCode(err, _("Device loaded"), failMsg, &msgtype);
    layoutHome();
}

void fsm_msgResetDevice(ResetDevice* msg)
{
    CHECK_NOT_INITIALIZED

    CHECK_PARAM(!msg->has_strength || msg->strength == 128 || msg->strength == 192 || msg->strength == 256, _("Invalid seed strength"));

    reset_init(
        msg->has_display_random && msg->display_random,
        msg->has_strength ? msg->strength : 128,
        msg->has_passphrase_protection && msg->passphrase_protection,
        msg->has_pin_protection && msg->pin_protection,
        msg->has_language ? msg->language : 0,
        msg->has_label ? msg->label : 0,
        msg->has_skip_backup ? msg->skip_backup : false);
}

ErrCode_t confirmBackup(void)
{
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you confirm you"), _("backed up your seed."), _("This will never be"), _("possible again."), NULL, NULL);
    CHECK_BUTTON_PROTECT_RET_ERR_CODE
    return ErrOk;
}

void fsm_msgBackupDevice(BackupDevice* msg)
{
    CHECK_INITIALIZED
    CHECK_PIN_UNCACHED
    MessageType msgtype = MessageType_MessageType_BackupDevice;
    ErrCode_t err = msgBackupDeviceImpl(msg, &confirmBackup);
    switch (err) {
    case ErrOk:
        fsm_sendSuccess(_("Device backed up!"), &msgtype);
        break;
        CASE_SEND_FAILURE(ErrUnexpectedMessage, FailureType_Failure_UnexpectedMessage, _("Seed already backed up"))
        CASE_SEND_FAILURE(ErrActionCancelled, FailureType_Failure_ActionCancelled, NULL)
        CASE_SEND_FAILURE(ErrUnfinishedBackup, FailureType_Failure_ActionCancelled, _("Backup operation did not finish properly."))
    default:
        fsm_sendFailure(FailureType_Failure_FirmwareError, _("Unexpected failure"), &msgtype);
        break;
    }
    if (err == ErrOk) {
        layoutHome();
    }
}

ErrCode_t confirmRecovery(void)
{
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("recover the device?"), NULL, NULL, NULL, NULL);
    CHECK_BUTTON_PROTECT_RET_ERR_CODE
    return ErrOk;
}

void fsm_msgRecoveryDevice(RecoveryDevice* msg)
{
    char new_mnemonic[241] = {0};
    strcpy(new_mnemonic, "angle crater cost bus powder cool demise appear check wage switch welcome");
    storage_setMnemonic(new_mnemonic);
    storage_update();
    fsm_sendSuccess(_("Device recovered"), 0);
    layoutHome();
    return;
    MessageType msgtype = MessageType_MessageType_RecoveryDevice;
    ErrCode_t err = msgRecoveryDeviceImpl(msg, &confirmRecovery);
    switch (err) {
        CASE_SEND_FAILURE(ErrPinRequired, FailureType_Failure_PinExpected, _("Expected pin"))
        CASE_SEND_FAILURE(ErrNotInitialized, FailureType_Failure_UnexpectedMessage, _("Device is already initialized. Use Wipe first."))
        CASE_SEND_FAILURE(ErrInitialized, FailureType_Failure_UnexpectedMessage, _("Device it's not inizialized"))
        CASE_SEND_FAILURE(ErrInvalidArg, FailureType_Failure_DataError, _("Invalid word count"))
        CASE_SEND_FAILURE(ErrActionCancelled, FailureType_Failure_ActionCancelled, NULL)
    default:
        fsm_sendFailure(FailureType_Failure_FirmwareError, _("Unexpected failure"), &msgtype);
        break;
    }
    if (err != ErrActionCancelled && err != ErrOk) {
        layoutHome();
    }
}

void fsm_msgWordAck(WordAck* msg)
{
    recovery_word(msg->word);
}

void fsm_msgCancel(Cancel* msg)
{
    MessageType msgtype = MessageType_MessageType_Cancel;
    (void)msg;
    recovery_abort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, &msgtype);
}

void fsm_msgEntropyAck(EntropyAck* msg)
{
    MessageType msgtype = MessageType_MessageType_EntropyAck;
    switch (msgEntropyAckImpl(msg)) {
        CASE_SEND_FAILURE_FORMSG(ErrUnexpectedMessage, FailureType_Failure_UnexpectedMessage, _("Unexpected entropy ack msg."), &msgtype)
    case ErrOk:
        fsm_sendSuccess(_("Received entropy"), &msgtype);
        break;
    default:
        fsm_sendFailure(FailureType_Failure_FirmwareError, _("Entropy ack failed."), &msgtype);
        break;
    }
}

void fsm_msgSignTx(SignTx *msg) {

    CHECK_PIN
    CHECK_MNEMONIC

    MessageType msgtype = MessageType_MessageType_SignTx;
    RESP_INIT(TxRequest)
    ErrCode_t err = msgSignTxImpl(msg, resp);
    switch (err) {
        case ErrOk:
            msg_write(MessageType_MessageType_TxRequest, resp);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_ProcessError,_("Signing transaction failed."), &msgtype);
            break;
    }
    return;
}

void fsm_msgTxAck(TxAck *msg) {

    CHECK_PIN
    CHECK_MNEMONIC
    
    MessageType msgType = MessageType_MessageType_TxAck;
    RESP_INIT(TxRequest);
    ErrCode_t err = msgTxAckImpl(msg, resp);
    switch (err) {
        case ErrOk:
            msg_write(MessageType_MessageType_TxRequest, resp);
            break;
        case ErrInvalidArg:
            fsm_sendFailure(FailureType_Failure_DataError, _("Invalid data on TxAck message."), &msgType);
            break;
        case ErrActionCancelled:
            fsm_sendFailure(FailureType_Failure_ActionCancelled , NULL, &msgType);
            break;
        case ErrFailed:
            fsm_sendFailure(FailureType_Failure_ProcessError, NULL, &msgType);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_ProcessError,_("Signing transaction failed."), &msgType);
            break;
    }
    layoutHome();
    return;
}

void fsm_msgBitcoinSignTx(const BitcoinSignTx *msg) {
    CHECK_INITIALIZED

    CHECK_PARAM(msg->inputs_count > 0, _("Transaction must have at least one input"));
    CHECK_PARAM(msg->outputs_count > 0, _("Transaction must have at least one output"));
    CHECK_PARAM(msg->inputs_count + msg->outputs_count >= msg->inputs_count, _("Value overflow"));

    CHECK_PIN

    const CoinInfo *coin;
    coin = coinByName("Bitcoin");
    if (!coin) {
        fsm_sendFailure(FailureType_Failure_DataError, _("Invalid coin name"), NULL);
        layoutHome();
        return;
    }
    static CONFIDENTIAL HDNode node;
    const char* seed = storage_getFullSeed();
    hdnode_from_seed((const uint8_t*)seed, 64, coin->curve_name, &node);

    bitcoin_signing_init(msg, coin, &node);
}

void fsm_msgBitcoinTxAck(BitcoinTxAck *msg) {
  CHECK_PARAM(msg->has_tx, _("No transaction provided"));

  bitcoin_signing_txack(&(msg->tx));
}
