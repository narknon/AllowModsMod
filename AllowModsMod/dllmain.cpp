#include <windows.h>
#ifdef TEXT
#undef TEXT
#endif
#include <DynamicOutput/Output.hpp>
#include <Mod/CppUserModBase.hpp>
#include <memoryapi.h>
#include <SigScanner/SinglePassSigScanner.hpp>
#include <Unreal/UnrealInitializer.hpp>

namespace RC
{
    /**
    * AllowModsMod: UE4SS c++ mod class defintion
    */
    class AllowModsMod : public RC::CppUserModBase {
    public:
        
        void patch_delegate();
        
        // constructor
        AllowModsMod() {
            ModVersion = STR("0.1");
            ModName = STR("AllowModsMod");
            ModAuthors = STR("Narknon + Truman");
            ModDescription = STR("Allows asset mods to load in PAYDAY 3");
            Output::send<LogLevel::Warning>(STR("[AllowModsMod]: Init.\n"));
            patch_delegate();
        }
        
        // destructor
        ~AllowModsMod() override {
            // fill when required
        }
        
        
};//class
    

    void AllowModsMod::patch_delegate()
    {
        uint8_t* function_address = nullptr;
        int8_t matches_found = 0;
        uint8_t* found_address = nullptr;
        SignatureContainer sig_address = [&]() -> SignatureContainer {
        return {
                    { { "" } }, // aob for function
                    [&](SignatureContainer& self) {
                        if(static_cast<uint8_t*>(self.get_match_address()) > function_address)
                        {
                            function_address = self.get_match_address();
                        }
                        ++matches_found;
                        if (matches_found == 2)
                        {
                            found_address = function_address;
                            self.get_did_succeed() = true;
                            return true;
                        }
                    return false;
                },
                [&](const SignatureContainer& self) {
                    if (self.get_did_succeed())
                    {
                        DWORD old;
                        VirtualProtect(found_address, 0x1, PAGE_EXECUTE_READWRITE, &old);
                        found_address[0] = 0xC3;
                        VirtualProtect(found_address, 0x1, old, &old);
                        Output::send<LogLevel::Warning>(STR("[AllowModsMod]: Delegate found and patched.\n"));
                    }
                    if (!self.get_did_succeed())
                    {
                        Output::send<LogLevel::Warning>(STR("[AllowModsMod]: Delegate not found. Unable to patch.\n"));
                    }
                }
            };
        }();
    std::vector<SignatureContainer> signature_containers_core{}; 
    signature_containers_core.emplace_back(sig_address);
    SinglePassScanner::SignatureContainerMap container_map{};
    container_map.emplace(ScanTarget::Core, signature_containers_core);
    uint32_t old_threads = SinglePassScanner::m_num_threads;
    SinglePassScanner::m_num_threads = 1;
    SinglePassScanner::start_scan(container_map);
    SinglePassScanner::m_num_threads = old_threads;
    }
}

/**
* export the start_mod() and uninstall_mod() functions to
* be used by the core ue4ss system to load in our dll mod
*/
#define MOD_EXPORT __declspec(dllexport) 
extern "C" {
    MOD_EXPORT RC::CppUserModBase* start_mod(){ return new RC::AllowModsMod(); }
    MOD_EXPORT void uninstall_mod(RC::CppUserModBase* mod) { delete mod; }
}
    




