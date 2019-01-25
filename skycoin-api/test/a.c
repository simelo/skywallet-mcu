

//
//
//
//
// START_TEST(test_aaaaa)
// {
//     ck_assert(is_digest("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132"));
//     ck_assert(!is_digest("02df09821cff4874198a1dbdc462d224bd99728eeed0241858792257623761")); //too short
//     ck_assert(!is_digest("02df09821cff4874198a1dbdc462d224bd99728eeed0241858792257623761256")); //too long
//     ck_assert(!is_digest("02df09821cff4874198a1dbdc462d224bd99728eeed0241858792257623761r")); //non hex digits
// }
// END_TEST

#include "libskycoin/include/libskycoin.h"

GoUint32 SKY_cipher_SecKeyFromHex(GoString p0, cipher__SecKey* p1) {
	return 0;
}
