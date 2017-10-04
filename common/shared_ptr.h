//
// Created by vytautas on 7/21/17.
//

#ifndef SGX_NETTING_SHARED_PTR_H
#define SGX_NETTING_SHARED_PTR_H


#ifdef ENCLAVE
#include "shared_ptr.h"

#include <enclave_state.h>

template<class T>
class shared_ptr
{
private:
    T* ptr;
    int* ref;
    void release()
    {
        if(ref == 0)
            return;
        --*ref;
        if(*ref==0)
        {
            //printf("%p free %p\n", this, ptr);
            delete ref;
            delete ptr;
        }
    }
public:
    shared_ptr():ptr(0),ref(0){}
    shared_ptr(T* x):ptr(x),ref(new int(1)){
        //printf("%p new ptr %p\n", this, ptr);
    }
    shared_ptr(const shared_ptr<T>& rhs):ptr(rhs.ptr),ref(rhs.ref)
    {
        //printf("%p copy %p\n", this, &rhs);
        if(ptr)
            (*ref)++;
    }
    ~shared_ptr()
    {
        //printf("%p del\n", this);
        release();
    }
    shared_ptr<T>& operator=(const shared_ptr<T>& rhs) {
        //printf("%p op copy << %p\n", this, rhs.ptr);
        if (ptr != rhs.ptr) {
            release();
            ptr = rhs.ptr;
            ref = rhs.ref;
            if(rhs.ptr)
                (*ref)++;
        }
        return *this;
    }
    T* get() const
    {
        return ptr;
    }
    T& operator *() const
    {
        return *ptr;
    }
    T* operator ->() const
    {
        return ptr;
    }

    // Comparison
    bool operator < (const shared_ptr<T>& rhs) const
    {
        return ptr < rhs.ptr;
    }
    bool operator > (const shared_ptr<T>& rhs) const
    {
        return ptr > rhs.ptr;
    }
    bool operator != (const shared_ptr<T>& rhs) const
    {
        return ptr != rhs.ptr;
    }
    bool operator == (const shared_ptr<T>& rhs) const
    {
        return ptr == rhs.ptr;
    }
};

#else
#include <memory>
using std::shared_ptr;
#endif

#endif //SGX_NETTING_SHARED_PTR_H
