
#include "base58.h"
#include "bitmaps.h"
#include "check_digest.h"
#include "droplet.h"
#include "firmware/error.h"
#include "fsm_impl.h"
#include "gettext.h"
#include "layout2.h"
#include "messages.pb.h"
#include "sha2.h"
#include "skyparams.h"
#include "skycoin_constants.h"
#include "skycoin_crypto.h"
#include "skycoin_signature.h"
#include "storage.h"
#include "util.h"
#include <inttypes.h>


#define CHECK_MNEMONIC_RET_ERR_CODE       \
    if (storage_hasMnemonic() == false) { \
        return ErrMnemonicRequired;       \
    }

ErrCode_t msgSkycoinSignMessageImpl(SkycoinSignMessage* msg, ResponseSkycoinSignMessage* msg_resp);
ErrCode_t msgSignTransactionMessageImpl(uint8_t* message_digest, uint32_t index, char* signed_message);
ErrCode_t msgSkycoinAddressImpl(SkycoinAddress* msg, ResponseSkycoinAddress* resp);
ErrCode_t msgSkycoinCheckMessageSignatureImpl(SkycoinCheckMessageSignature* msg, Success* successResp, Failure* failureResp);
ErrCode_t msgTransactionSignImpl(TransactionSign* msg, ErrCode_t (*)(char*, char*, TransactionSign*, uint32_t), ResponseTransactionSign*);
ErrCode_t msgSignTxImpl(SignTx* msg,TxRequest* resp);
ErrCode_t msgTxAckImpl(TxAck* msg, TxRequest* resp);
