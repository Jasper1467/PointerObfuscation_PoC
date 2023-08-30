#pragma once

#include <vector>
#include <atomic>

#if defined(_WIN64)
typedef unsigned __int64 ULONG_PTR;
#else
typedef unsigned long ULONG_PTR;
#endif

typedef unsigned long ULONG;
typedef ULONG *PULONG;
typedef ULONG_PTR DWORD_PTR;
typedef void *PVOID;

namespace ptrobf
{
    struct Data_t
    {
        Data_t(void *pPtr)
        {
            for (size_t i = 0; i < 128; i++)
            {
                if (i == m_nRealIndex)
                    m_vecPtr.push_back(pPtr);
            }
        }

        std::vector<void *> m_vecPtr = {};
        const int m_nRealIndex = 0x75;
    };

    class CStorage
    {
    private:
        inline static int REAL_DATA_INDEX_MINUS_ONE = __TIME__[0] * 137 + __TIME__[1] * 5 + __TIME__[2] * 7;
        std::vector<std::vector<Data_t>> m_vecData = {};

    public:
        void AddData(Data_t Data)
        {
            m_vecData.at(REAL_DATA_INDEX_MINUS_ONE + 1).push_back(Data);
        }

        std::vector<Data_t> GetData() const { return m_vecData[REAL_DATA_INDEX_MINUS_ONE + 1]; }

        void *GetDataPointer(void *pEncryptedPtr) const
        {
            auto Data = GetData();
            for (size_t i = 0; i < Data.size(); i++)
            {
                if (Data[i].m_vecPtr[Data[i].m_nRealIndex] == pEncryptedPtr)
                    return Data[i].m_vecPtr[0];
            }

            return nullptr;
        }
    };

    inline CStorage g_Storage;

    static DWORD_PTR g_PointerObfuscator;

#ifdef _WIN64
    inline constexpr int ROT_BITS = 64;
#else
    inline constexpr int ROT_BITS = 32
#endif

    inline static DWORD_PTR rotl_ptr(DWORD_PTR num, int shift)
    {
        shift &= ROT_BITS - 1;
        return (num << shift) | (num >> (ROT_BITS - shift));
    }

    inline static DWORD_PTR rotr_ptr(DWORD_PTR num, int shift)
    {
        shift &= ROT_BITS - 1;
        return (num >> shift) | (num << (ROT_BITS - shift));
    }

    inline ULONG Uniform(PULONG Seed)
    {
        constexpr ULONG Multiplier = ((ULONG)(0x80000000ul - 19)); // 2**31 - 19
        constexpr ULONG Increment = ((ULONG)(0x80000000ul - 61));  // 2**31 - 61
        constexpr ULONG Modulus = ((ULONG)(0x80000000ul - 1));     // 2**31 - 1

        *Seed = ((Multiplier * (*Seed)) + Increment) % Modulus;
        return *Seed;
    }

    struct timespec
    {
        long tv_sec;
        long tv_nsec;
    };                                            // header part

    inline static DWORD_PTR GetPointerObfuscator(void)
    {
        if (!g_PointerObfuscator)
        {
            ULONG seed = __TIME__[0] * 137 + __TIME__[1] * 5 + __TIME__[2] * 7 + __TIME__[3] * 11 + __TIME__[4] * 13 + __TIME__[5] * 17;
            ULONG_PTR rand;
            // generate a random value for the obfuscator
            rand = Uniform(&seed);

            // handle 64bit pointers
            rand ^= Uniform(&seed) << ((sizeof(DWORD_PTR) - sizeof(ULONG)) * 8);

            // Set the high bits so dereferencing obfuscated pointers will (usually) crash
            rand |= 0xc0000000 << ((sizeof(DWORD_PTR) - sizeof(ULONG)) * 8);

            std::atomic_compare_exchange_strong(std::atomic<void*>(&g_PointerObfuscator), std::atomic<void *>(&rand), NULL);
        }
        return g_PointerObfuscator;
    }

    inline void Encrypt(void *pPtr)
    {
        DWORD_PTR pdwPtrVal = (DWORD_PTR)pPtr;
        DWORD_PTR pdwCookie = GetPointerObfuscator();
        pdwPtrVal = (pdwPtrVal ^ pdwCookie);

        g_Storage.AddData(Data_t((void *)rotr_ptr(pdwPtrVal, pdwCookie)));
    }

    inline void *Decrypt(void *pPtr)
    {
        auto pTargetPtr = g_Storage.GetDataPointer(pPtr);
        if (!pTargetPtr)
            return nullptr;

        DWORD_PTR pdwPtrVal = (DWORD_PTR)pTargetPtr;
        DWORD_PTR pdwCookie = GetPointerObfuscator();
        pdwPtrVal = rotl_ptr(pdwPtrVal, pdwCookie);
        return (PVOID)(pdwPtrVal ^ pdwCookie);
    }
} // namespace ptrobf
