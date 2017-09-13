//
// Created by vytautas on 9/13/17.
//

#include <map>
#include "app_jni.h"

#include "app.h"

#include <iostream>

using namespace std;

#include "util.h"
#include "jni_util.h"


jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    bool enclave_changed = false;
    app_init(enclave_changed);
    return JNI_VERSION_1_8;
}


JNIEXPORT jboolean JNICALL Java_App_sgx_1available
        (JNIEnv *, jclass)
{
    return (jboolean)true; // FIXME: assumes enclave init is a good enough test
}

JNIEXPORT void JNICALL Java_App_encryptTrades
        (JNIEnv * env, jclass, jobject trade_list)
{
    // List class things
    jclass cList = env->FindClass("java/util/List");

    jmethodID mSize = env->GetMethodID(cList, "size", "()I");
    jmethodID mGet = env->GetMethodID(cList, "get", "(I)Ljava/lang/Object;");

    jint size = env->CallIntMethod(trade_list, mSize);

    // Other class things
    jclass cStandardId = env->FindClass("data/StandardId");
    jclass cTrade = env->FindClass("data/Trade");

    jfieldID fScheme = env->GetFieldID(cStandardId, "scheme", "Ljava/lang/String;");
    assert(fScheme != 0);
    jfieldID fValue = env->GetFieldID(cStandardId, "value", "Ljava/lang/String;");
    assert(fValue != 0);

    jfieldID fParty = env->GetFieldID(cTrade, "party", "Ldata/StandardId;");
    assert(fParty != 0);
    jfieldID fCParty = env->GetFieldID(cTrade, "counter_party", "Ldata/StandardId;");
    assert(fCParty != 0);
    jfieldID fTradeValue = env->GetFieldID(cTrade, "value", "J");
    assert(fTradeValue != 0);

    vector<ClearedTrade> trades;
    map<string, shared_ptr<StandardId>> ps_to_p;

    // walk through and fill the vector
    for(jint i=0;i<size;i++) {
        jobject j_trade = env->CallObjectMethod(trade_list, mGet, i);
        jobject j_party_a = env->GetObjectField(j_trade, fParty);
        jobject j_party_b = env->GetObjectField(j_trade, fCParty);
        assert(j_trade != 0);
        assert(j_party_a != 0);
        assert(j_party_b != 0);

        int64_t value = env->GetLongField(j_trade, fTradeValue);
        ClearedTrade trade;

        party_id_t p_a = get_party(
                JString(env, env->GetObjectField(j_party_a, fScheme)).data(),
                JString(env, env->GetObjectField(j_party_a, fValue)).data(),
                ps_to_p
            );
        party_id_t p_b = get_party(
                JString(env, env->GetObjectField(j_party_b, fScheme)).data(),
                JString(env, env->GetObjectField(j_party_b, fValue)).data(),
                ps_to_p
        );

        ClearedTrade t;
        t.party = p_a;
        t.counter_party = p_b;
        t.value = value;

        trades.push_back(t);
    }

    cout << "Java given trades to encrypt:\n" << trades << endl;

}