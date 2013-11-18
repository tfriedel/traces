#ifndef VDKTLS_H_
#define VDKTLS_H_

#include "VDK.h"
#include <memory.h>

template <class T> class VdkTLS {
protected:
    DWORD index;
    T* getMemPtr(bool autoCreate = true) const {
        T* mem = (T*) VDK::GetThreadSlotValue(index);
        if (!mem && autoCreate) {
            mem = (T*) malloc(sizeof(T));
            VDK::SetThreadSlotValue(index, mem);
        }
        return mem;
    }
public:
    VdkTLS(): index(0) {
        VDK::AllocateThreadSlotEx(&index, free);
    }
    ~VdkTLS() {
        VDK::FreeThreadSlot(index);
    }
    operator T&() const {
        return *getMemPtr();
    }
    T& operator=(const T& value) {
        T* mem = getMemPtr();
        *mem = value;
        return *mem;
    }
};

#endif /*VDKTLS_H_*/
