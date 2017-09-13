//
// Created by vytautas on 9/13/17.
//

#ifndef SGX_NETTING_JNI_UTIL_H
#define SGX_NETTING_JNI_UTIL_H

#include <jni.h>
struct JString
{
    JNIEnv* m_env;
    jstring m_s;
    const char* m_data;
    JString(JNIEnv* env, jobject j_s){
        if(j_s == 0)
            throw std::runtime_error("String null!");
        m_env = env;
        m_s = (jstring)j_s;

        m_data = env->GetStringUTFChars(m_s, 0);
    }

    ~JString(){
        m_env->ReleaseStringUTFChars(m_s, m_data);
    }

    const char* data(){
        return m_data;
    }
    operator const char*(){
        return m_data;
    }
};

inline party_id_t get_party(const string& scheme, const string& value, map<string, shared_ptr<StandardId>>& ps_to_p)
{
    party_id_t p;

    string k = scheme+"~"+value;
    auto it = ps_to_p.find(k);
    if(it == ps_to_p.end()) {
        ps_to_p[k] = p = party_id_t(new StandardId(scheme, value));
    } else
        p = it->second;

    return p;
}
#endif //SGX_NETTING_JNI_UTIL_H
