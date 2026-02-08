#include "aida_pro.hpp"

#include <algorithm>

namespace localization {

static std::string to_lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool is_russian()
{
    std::string lang = to_lower(g_settings.response_language);
    return lang == "russian" || lang == "ru" || lang == "русский" || lang == "russian (ru)";
}

const char* tr(const char* english, const char* russian)
{
    return is_russian() ? russian : english;
}

} // namespace localization
