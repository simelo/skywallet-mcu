/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include "fsm_impl.h"

#include <libopencm3/stm32/flash.h>


#include "bip32.h"
#include "bip39.h"
#include "base58.h"
#include "check_digest.h"
#include "droplet.h"
#include "entropy.h"
#include "fsm.h"
#include "fsm_impl.h"
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
#include "skycoin_constants.h"
#include "skycoin_crypto.h"
#include "skycoin_signature.h"
#include "skyparams.h"
#include "skywallet.h"
#include "storage.h"
#include "usb.h"
#include "util.h"
#include <inttypes.h>
#include <stdio.h>

#define MNEMONIC_STRENGTH_12 128
#define MNEMONIC_STRENGTH_24 256
#define INTERNAL_ENTROPY_SIZE SHA256_DIGEST_LENGTH

uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

extern uint32_t strength;
extern bool skip_backup;
extern uint8_t int_entropy[INTERNAL_ENTROPY_SIZE];

ErrCode_t msgEntropyAckImpl(EntropyAck* msg)
{
    _Static_assert(EXTERNAL_ENTROPY_MAX_SIZE == sizeof(msg->entropy.bytes),
        "External entropy size does not match.");
    if (msg->entropy.size > sizeof(msg->entropy.bytes)) {
      return ErrInvalidArg;
    }
    if (!msg->has_entropy) {
        return ErrEntropyNotNeeded;
    }
    set_external_entropy(msg->entropy.bytes, msg->entropy.size);
    return ErrOk;
}

ErrCode_t msgGenerateMnemonicImpl(GenerateMnemonic* msg, void (*random_buffer_func)(uint8_t* buf, size_t len))
{
    CHECK_NOT_INITIALIZED_RET_ERR_CODE
    strength = MNEMONIC_STRENGTH_12;
    if (msg->has_word_count) {
        switch (msg->word_count) {
        case MNEMONIC_WORD_COUNT_12:
            strength = MNEMONIC_STRENGTH_12;
            break;
        case MNEMONIC_WORD_COUNT_24:
            strength = MNEMONIC_STRENGTH_24;
            break;
        default:
            return ErrInvalidArg;
        }
    }
    // random buffer + entropy pool => mix256 => internal entropy
    uint8_t data[sizeof(int_entropy)];
    random_buffer_func(data, sizeof(data));
    entropy_salt_mix_256(data, sizeof(data), int_entropy);
    memset(data, 0, sizeof(data));
    const char* mnemonic = mnemonic_from_data(int_entropy, strength / 8);
    memset(int_entropy, 0, sizeof(int_entropy));
    if (!mnemonic) {
        return ErrInvalidValue;
    }
    if (!mnemonic_check(mnemonic)) {
        return ErrInvalidChecksum;
    }
    storage_setMnemonic(mnemonic);
    TxSignContext* ctx = TxSignCtx_Get();
    if(ctx != NULL){
        ctx->mnemonic_change = true;
    }
    storage_setNeedsBackup(true);
    storage_setPassphraseProtection(
        msg->has_passphrase_protection && msg->passphrase_protection);
    storage_update();
    return ErrOk;
}

ErrCode_t fsm_getKeyPairAtIndex(uint32_t nbAddress, uint8_t* pubkey, uint8_t* seckey, ResponseSkycoinAddress* respSkycoinAddress, uint32_t start_index)
{
    const char* mnemo = storage_getFullSeed();
    uint8_t seed[33] = {0};
    uint8_t nextSeed[SHA256_DIGEST_LENGTH] = {0};
    size_t size_address = 36;
    _Static_assert(
            sizeof(respSkycoinAddress->addresses[0]) == 36,
            "invalid address bffer size");
    if (mnemo == NULL || nbAddress == 0) {
        return ErrInvalidArg;
    }
    if (0 != deterministic_key_pair_iterator((const uint8_t*)mnemo, strlen(mnemo), nextSeed, seckey, pubkey)) {
        return ErrFailed;
    }
    if (respSkycoinAddress != NULL && start_index == 0) {
        if (!skycoin_address_from_pubkey(pubkey, respSkycoinAddress->addresses[0], &size_address)) {
            return ErrFailed;
        }
        respSkycoinAddress->addresses_count++;
    }
    memcpy(seed, nextSeed, 32);
    size_t max_addresses =
            sizeof(respSkycoinAddress->addresses)
            / sizeof(respSkycoinAddress->addresses[0]);
    if (nbAddress + start_index - 1 > max_addresses) {
        return ErrInvalidArg;
    }
    for (uint32_t i = 0; i < nbAddress + start_index - 1; ++i) {
        if (0 != deterministic_key_pair_iterator(seed, 32, nextSeed, seckey, pubkey)) {
            return ErrFailed;
        }
        memcpy(seed, nextSeed, 32);
        seed[32] = 0;
        if (respSkycoinAddress != NULL && ((i + 1) >= start_index)) {
            size_address = 36;
            if (!skycoin_address_from_pubkey(pubkey, respSkycoinAddress->addresses[respSkycoinAddress->addresses_count], &size_address)) {
                return ErrFailed;
            }
            respSkycoinAddress->addresses_count++;
        }
    }
    return ErrOk;
}

ErrCode_t verifyLanguage(char* lang)
{
    // FIXME: Check for supported language name. Only english atm.
    return (!strcmp(lang, "english")) ? ErrOk : ErrInvalidValue;
}

ErrCode_t msgApplySettingsImpl(ApplySettings* msg)
{
    _Static_assert(
        sizeof(msg->label) == DEVICE_LABEL_SIZE,
        "device label size inconsitent betwen protocol and final storage");
    CHECK_PRECONDITION_RET_ERR_CODE(msg->has_label || msg->has_language || msg->has_use_passphrase || msg->has_homescreen,
        _("No setting provided"));
    if (msg->has_label) {
        storage_setLabel(msg->label);
    }
    if (msg->has_language) {
        CHECK_PARAM_RET_ERR_CODE(verifyLanguage(msg->language) == ErrOk, NULL);
        storage_setLanguage(msg->language);
    }
    if (msg->has_use_passphrase) {
        storage_setPassphraseProtection(msg->use_passphrase);
    }
    if (msg->has_homescreen) {
        storage_setHomescreen(msg->homescreen.bytes, msg->homescreen.size);
    }
    storage_update();
    return ErrOk;
}

#if !defined(EMULATOR) || !EMULATOR
#include "memory.h"
#endif
ErrCode_t msgGetFeaturesImpl(Features* resp)
{
    resp->has_vendor = true;
    strlcpy(resp->vendor, "Skycoin Foundation", sizeof(resp->vendor));
#if VERSION_IS_SEMANTIC_COMPLIANT == 1
#ifdef VERSION_MAJOR
    resp->has_fw_major = true;
    resp->fw_major = VERSION_MAJOR;
#endif // VERSION_MAJOR
#ifdef VERSION_MINOR
    resp->has_fw_minor = true;
    resp->fw_minor = VERSION_MINOR;
#endif // VERSION_MINOR
#ifdef VERSION_PATCH
    resp->has_fw_patch = true;
    resp->fw_patch = VERSION_PATCH;
#endif // VERSION_PATCH
#else  // VERSION_IS_SEMANTIC_COMPLIANT == 1
#ifdef APPVER
    resp->has_fw_version_head = true;
    sprintf(resp->fw_version_head, "%x", APPVER);
#endif // APPVER
#endif // VERSION_IS_SEMANTIC_COMPLIANT == 1
    resp->has_device_id = true;
    strlcpy(resp->device_id, storage_uuid_str, sizeof(resp->device_id));
    resp->has_pin_protection = true;
    resp->pin_protection = storage_hasPin();
    resp->has_passphrase_protection = true;
    resp->passphrase_protection = storage_hasPassphraseProtection();
    resp->has_bootloader_hash = true;
    resp->bootloader_hash.size = memory_bootloader_hash(resp->bootloader_hash.bytes);
    if (storage_getLanguage()) {
        resp->has_language = true;
        strlcpy(resp->language, storage_getLanguage(), sizeof(resp->language));
    }
    if (storage_getLabel()) {
        resp->has_label = true;
        strlcpy(resp->label, storage_getLabel(), sizeof(resp->label));
    }
    resp->has_initialized = true;
    resp->initialized = storage_isInitialized();
    resp->has_pin_cached = true;
    resp->pin_cached = session_isPinCached();
    resp->has_passphrase_cached = true;
    resp->passphrase_cached = session_isPassphraseCached();
    resp->has_needs_backup = true;
    resp->needs_backup = storage_needsBackup();
    resp->has_model = true;
    strlcpy(resp->model, "1", sizeof(resp->model));
    resp->has_firmware_features = true;
#if defined(EMULATOR) && EMULATOR
    resp->firmware_features |= FirmwareFeatures_IsEmulator;
#else
    resp->firmware_features |= (uint32_t)(memory_rdp_level() << FirmwareFeatures_IsEmulator);
#endif

#if DISABLE_GETENTROPY_CONFIRM
    resp->firmware_features |= FirmwareFeatures_RequireGetEntropyConfirm;
#endif
#if defined(ENABLE_GETENTROPY) && ENABLE_GETENTROPY
    resp->firmware_features |= FirmwareFeatures_IsGetEntropyEnabled;
#endif

    return ErrOk;
}

ErrCode_t msgPingImpl(Ping* msg)
{
    RESP_INIT(Success);

    if (msg->has_pin_protection && msg->pin_protection) {
        CHECK_PIN_RET_ERR_CODE
    }

    if (msg->has_passphrase_protection && msg->passphrase_protection) {
        if (!protectPassphrase()) {
            return ErrActionCancelled;
        }
    }

    if (msg->has_message) {
        resp->has_message = true;
        memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
    }
    msg_write(MessageType_MessageType_Success, resp);
    return ErrOk;
}

ErrCode_t msgChangePinImpl(ChangePin* msg, const char* (*funcRequestPin)(PinMatrixRequestType, const char*))
{
    bool removal = msg->has_remove && msg->remove;
    if (removal) {
        storage_setPin("");
        storage_update();
    } else {
        if (!protectChangePinEx(funcRequestPin)) {
            return ErrPinMismatch;
        }
    }
    return ErrOk;
}

ErrCode_t msgWipeDeviceImpl(WipeDevice* msg)
{
    (void)msg;
    storage_wipe();
    // the following does not work on Mac anyway :-/ Linux/Windows are fine, so it is not needed
    // usbReconnect(); // force re-enumeration because of the serial number change
    // fsm_sendSuccess(_("Device wiped"));
    return ErrOk;
}

ErrCode_t msgSetMnemonicImpl(SetMnemonic* msg)
{
    CHECK_MNEMONIC_CHECKSUM_RET_ERR_CODE
    storage_setMnemonic(msg->mnemonic);
    TxSignContext* ctx = TxSignCtx_Get();
    if(ctx != NULL){
        ctx->mnemonic_change = true;
    }
    storage_setNeedsBackup(true);
    storage_update();
    //fsm_sendSuccess(_(msg->mnemonic));
    return ErrOk;
}

ErrCode_t msgGetEntropyImpl(GetRawEntropy* msg, Entropy* resp, void (*random_buffer_func)(uint8_t* buf, size_t len))
{
    (void)msg;
    (void)resp;
    (void)random_buffer_func;
#if defined(EMULATOR) && EMULATOR
    return ErrNotImplemented;
#else
#if !defined(ENABLE_GETENTROPY) || !ENABLE_GETENTROPY
    return ErrNotImplemented;
#endif // ENABLE_GETENTROPY
    uint32_t len = (msg->size > 1024) ? 1024 : msg->size;
    resp->entropy.size = len;
    random_buffer_func(resp->entropy.bytes, len);
    return ErrOk;
#endif // EMULATOR
}

ErrCode_t msgLoadDeviceImpl(LoadDevice* msg)
{
    if (msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum)) {
        CHECK_MNEMONIC_CHECKSUM_RET_ERR_CODE
    }

    storage_loadDevice(msg);
    //fsm_sendSuccess(_("Device loaded"));
    return ErrOk;
}

ErrCode_t msgBackupDeviceImpl(BackupDevice* msg, ErrCode_t (*funcConfirmBackup)(void))
{
    (void)msg;
    if (!storage_needsBackup()) {
        //fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Seed already backed up"));
        return ErrUnexpectedMessage;
    }
    ErrCode_t err = reset_backup(true);
    if (err != ErrOk) {
      return err;
    }

    err = funcConfirmBackup();
    if (err != ErrOk) {
        return err;
    }
    if (storage_unfinishedBackup()) {
        // fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Backup operation did not finish properly."));
        // layoutHome();
        return ErrUnfinishedBackup;
    }
    storage_setNeedsBackup(false);
    storage_update();
    // fsm_sendSuccess(_("Device backed up!"));
    return ErrOk;
}

ErrCode_t msgRecoveryDeviceImpl(RecoveryDevice* msg, ErrCode_t (*funcConfirmRecovery)(void))
{
    const bool dry_run = msg->has_dry_run ? msg->dry_run : false;
    if (dry_run) {
        CHECK_PIN_RET_ERR_CODE
        CHECK_INITIALIZED_RET_ERR_CODE
    } else {
        CHECK_NOT_INITIALIZED_RET_ERR_CODE
    }

    CHECK_PARAM_RET_ERR_CODE(!msg->has_word_count || msg->word_count == 12 || msg->word_count == 24, _("Invalid word count"));

    if (!dry_run) {
        ErrCode_t err = funcConfirmRecovery();
        if (err != ErrOk) {
            return err;
        }
    }
    char current_label[DEVICE_LABEL_SIZE];
    strncpy(current_label, storage_getLabel(), sizeof(current_label));

    recovery_init(
        msg->has_word_count ? msg->word_count : 12,
        msg->has_passphrase_protection && msg->passphrase_protection,
        msg->has_pin_protection && msg->pin_protection,
        msg->has_language ? msg->language : 0,
        (msg->has_label && strlen(msg->label) > 0)? msg->label: current_label,
        dry_run);
    return ErrOk;
}
