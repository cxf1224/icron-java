package com.zeroone.libicc;

public class LibIccException extends Exception {
    private static final String[] MESSAGES = {
            "ICC_OK",
            "ICC_KEYPAIR",
            "ICC_ENCRYPT",
            "ICC_DECRYPT",
            "ICC_IND_CCA2",
            "ICC_INVALID_DATA",
            "ICC_HASH",
            "ICC_WEIGHT",
            "ICC_RANDOM",
            "ICC_BAD_CONTEXT",
            "ICC_MEMORY",
            "ICC_UNRECOGNIZED",
            "ICC_SIGN",
            "ICC_VERIFY",
            "ICC_BAD_PK",
            "ICC_BAD_SK",
            "ICC_UNKNOWN"
    };
    private final int mErrCode;
    public LibIccException(int errCode) {
        mErrCode = errCode;
    }

    public int getErrCode() {
        return mErrCode;
    }

    @Override
    public String getMessage() {
        if (mErrCode >= 0 && mErrCode < MESSAGES.length) {
            return MESSAGES[mErrCode];
        }
        return "ICC_ERROR " + mErrCode;
    }
}
