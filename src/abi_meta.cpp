#include <string>

#include "obn/abi_export.hpp"
#include "obn/config.hpp"

#ifndef OBN_VERSION_STRING
#    error "OBN_VERSION_STRING is not defined; build through the top-level ./configure or pass -DOBN_VERSION=... to cmake"
#endif

// Returned to Studio's NetworkAgent::get_version(). Studio validates the
// first 8 characters against its own SLIC3R_VERSION in
// check_networking_version() (see src/slic3r/GUI/GUI_App.cpp). The value
// is injected from -DOBN_VERSION=... at CMake configure time; the
// top-level ./configure auto-detects it from the installed
// BambuStudio.conf, refusing to pick a stale default. A
// <config_dir>/reported_version file (written by the open_bambu_networking
// installer when the host series is one this build does not ship) wins
// over the compiled-in value, so a fixed-ABI build can satisfy a future
// series without a rebuild.
OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_BEGIN
OBN_ABI std::string bambu_network_get_version()
{
    if (const std::string ovr = obn::config::reported_version(); !ovr.empty())
        return ovr;
    return std::string(OBN_VERSION_STRING);
}
OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_END

// Studio passes `true` for debug builds and `false` for release. A plugin
// compiled for the other mode should return false; we always claim
// consistency because a single release-mode .so must work with both Studio
// builds.
OBN_ABI bool bambu_network_check_debug_consistent(bool /*is_debug*/)
{
    return true;
}
