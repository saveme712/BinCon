#include "stub.h"

#include <bc_iat.h>

namespace bc
{
    HRSRC hook_find_resource(HMODULE m, LPCSTR rsc, LPCSTR type)
    {
        UNREFERENCED_PARAMETER(m);
        UNREFERENCED_PARAMETER(type);

        auto pca = (packed_resource*)((char*)BC.app + BC.app->off_to_resources.off);
        for (auto i = 0ull; i < BC.app->off_to_resources.num_elements; i++)
        {
            auto pc = &pca[i];
            if (pc->id == (uint16_t)rsc)
            {
                return (HRSRC)pc;
            }
        }
        return NULL;
    }

    HGLOBAL hook_load_resource(HMODULE m, HRSRC src)
    {
        UNREFERENCED_PARAMETER(m);
        return (HGLOBAL)src;
    }

    LPVOID hook_lock_resource(HGLOBAL global)
    {
        if (!global)
        {
            return NULL;
        }

        auto packed = (packed_resource*)global;
        return (char*)BC.app + packed->off_to_data.get();
    }

    DWORD hook_sizeof_resource(HMODULE m, HRSRC src)
    {
        UNREFERENCED_PARAMETER(m);

        if (!src)
        {
            return NULL;
        }

        auto packed = (packed_resource*)src;
        return (DWORD)packed->size_of_data;
    }

    /// <summary>
    /// Our hook for GetProcAddress. This allows us to query packer information without
    /// a custom entry-point.
    /// </summary>
    void* hook_get_proc_address(HMODULE m, const char* name)
    {
        BEGIN_VM(__FUNCTION__);

        disable_tf();
        auto peb = peb_walker::tib();
        void* proc = NULL;

        if (m == (HMODULE)0xBC && !strcmp(name, xorstr_("pack_interface")))
        {
            return &BC.cur_chal_entry;
        }

        if (!m)
        {
            goto _ret;
        }

        proc = peb.resolve_function((char*)m, name);
        if (!proc)
        {
            proc = (void*)IAT.GetProcAddress(m, name);
        }

        if (!proc)
        {
            ERR("Failed to get proc address " << m << " " << name);
        }

    _ret:
        END_VM(__FUNCTION__);
        return proc;
    }

}