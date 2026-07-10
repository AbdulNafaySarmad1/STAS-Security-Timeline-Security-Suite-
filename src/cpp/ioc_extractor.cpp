#include "ioc_extractor.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cmath>
#include <iomanip>
#include <regex>
#include <sstream>
#include <utility>

namespace {
uint64_t fnv1a64(const std::string& value) {
    uint64_t hash = 14695981039346656037ull;
    for (unsigned char ch : value) {
        hash ^= ch;
        hash *= 1099511628211ull;
    }
    return hash;
}

std::vector<std::string> splitLabels(const std::string& domain) {
    std::vector<std::string> labels;
    std::stringstream stream(domain);
    std::string label;
    while (std::getline(stream, label, '.')) {
        if (!label.empty()) {
            labels.push_back(label);
        }
    }
    return labels;
}

bool isHexString(const std::string& value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}
}

IOCExtractor::IOCExtractor()
    : known_legitimate_domains({
          "microsoft.com", "windows.com", "live.com", "office.com", "office365.com",
          "azure.com", "msftconnecttest.com", "msftncsi.com", "github.com",
          "google.com", "gstatic.com", "googleapis.com", "mozilla.org",
          "digicert.com", "verisign.com", "symantec.com", "adobe.com"
      }),
      valid_tlds({
          "com", "net", "org", "info", "biz", "io", "co", "ru", "cn", "top",
          "xyz", "site", "online", "icu", "live", "shop", "club", "win", "su",
          "me", "cc", "pw", "pro", "space", "app", "dev", "cloud", "tech",
          "email", "gov", "edu", "mil", "uk", "de", "fr", "nl", "br", "in",
          "jp", "kr", "au", "ca", "us", "pl", "it", "es", "se", "no", "fi",
          "ch", "at", "be", "cz", "ua", "onion"
      }) {}

std::vector<IOC> IOCExtractor::extract(const std::vector<std::string>& strings) const {
    std::vector<StringArtifact> artifacts;
    artifacts.reserve(strings.size());
    for (const auto& value : strings) {
        artifacts.push_back({value, -1});
    }
    return extract(artifacts);
}

std::vector<IOC> IOCExtractor::extract(const std::vector<StringArtifact>& strings) const {
    std::vector<IOC> iocs;
    std::set<std::string> seen;

    for (const auto& artifact : strings) {
        extractFromString(artifact, iocs, seen);
    }

    std::sort(iocs.begin(), iocs.end(), [](const IOC& left, const IOC& right) {
        if (left.confidence != right.confidence) {
            return left.confidence > right.confidence;
        }
        if (left.type != right.type) {
            return left.type < right.type;
        }
        return left.value < right.value;
    });

    return iocs;
}

void IOCExtractor::extractFromString(
    const StringArtifact& artifact,
    std::vector<IOC>& out,
    std::set<std::string>& seen) const {
    const std::string& text = artifact.value;

    const std::vector<std::pair<std::string, std::regex>> regexes = {
        {"URL", std::regex(R"(\b(?:https?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)", std::regex::icase)},
        {"IPV4", std::regex(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)")},
        {"IPV6", std::regex(R"(\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b)")},
        {"IPV6", std::regex(R"(\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b)")},
        {"ONION", std::regex(R"(\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b)", std::regex::icase)},
        {"DOMAIN", std::regex(R"(\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b)")},
        {"WINDOWS_PATH", std::regex(R"((?:[A-Za-z]:\\|%[A-Za-z0-9_]+%\\|\\\\[A-Za-z0-9_.-]+\\[A-Za-z0-9_$.-]+\\)[^"'<>|]{2,260})", std::regex::icase)},
        {"NAMED_PIPE", std::regex(R"(\\\\\.\\pipe\\[A-Za-z0-9_.\-$]+)", std::regex::icase)},
        {"REGISTRY_KEY", std::regex(R"(\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[A-Za-z0-9_ .\\{}$-]{3,260})", std::regex::icase)},
        {"BITCOIN", std::regex(R"(\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b)", std::regex::icase)},
        {"ETHEREUM", std::regex(R"(\b0x[a-fA-F0-9]{40}\b)")},
        {"MONERO", std::regex(R"(\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b)")},
        {"API_KEY", std::regex(R"(\b(?:sk|pk)-[A-Za-z0-9_-]{16,}\b|\bAKIA[0-9A-Z]{16}\b)", std::regex::icase)},
        {"JWT", std::regex(R"(\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)")},
        {"PRIVATE_KEY", std::regex(R"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")},
        {"TELEGRAM_BOT_TOKEN", std::regex(R"(\b\d{6,12}:[A-Za-z0-9_-]{35}\b)")},
        {"DISCORD_WEBHOOK", std::regex(R"(https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)", std::regex::icase)},
        {"EMAIL", std::regex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b)")},
        {"MUTEX", std::regex(R"(\b(?:Global\\|Local\\)?(?:mutex|mutant|m_[A-Za-z0-9]|rat|bot|loader|malware|stub)[A-Za-z0-9_.\-{}]{4,80}\b)", std::regex::icase)},
        {"SERVICE_NAME", std::regex(R"(\b(?:svc|service|srv|update|updater|winsvc|winupdate)[A-Za-z0-9_.-]{4,64}\b)", std::regex::icase)}
    };

    for (const auto& entry : regexes) {
        const std::string& type = entry.first;
        const std::regex& pattern = entry.second;

        for (std::sregex_iterator it(text.begin(), text.end(), pattern), end; it != end; ++it) {
            std::string value = trimTrailingPunctuation(it->str());
            if (type == "IPV4" && isExcludedIpv4(value)) {
                continue;
            }
            if ((type == "DOMAIN" || type == "ONION") && (!hasValidTld(value) || isLegitimateDomain(value))) {
                continue;
            }
            if (type == "DOMAIN" && value.find('@') != std::string::npos) {
                continue;
            }
            if (type == "IPV6" && value.find("::") == std::string::npos && std::count(value.begin(), value.end(), ':') < 2) {
                continue;
            }

            float confidence = 0.75f;
            if (type == "URL" || type == "DISCORD_WEBHOOK" || type == "TELEGRAM_BOT_TOKEN"
                || type == "PRIVATE_KEY" || type == "JWT" || type == "ETHEREUM" || type == "BITCOIN") {
                confidence = 0.95f;
            } else if (type == "DOMAIN" || type == "SERVICE_NAME" || type == "MUTEX") {
                confidence = 0.70f;
            }

            addIoc(out, seen, type, value, confidence, text, artifact.file_offset, static_cast<size_t>(it->position()));
        }
    }

    const std::regex assignment_pattern(
        R"((?:password|passwd|pwd|pass|secret|token|wallet|seed|mnemonic|api[_-]?key)\s*[:=]\s*["']?([^"'\s;]{8,128}))",
        std::regex::icase);
    for (std::sregex_iterator it(text.begin(), text.end(), assignment_pattern), end; it != end; ++it) {
        const std::string value = trimTrailingPunctuation((*it)[1].str());
        if (isLikelyPassword(value)) {
            addIoc(
                out,
                seen,
                "HARDCODED_PASSWORD",
                value,
                0.80f,
                text,
                artifact.file_offset,
                static_cast<size_t>(it->position(1)));
        }
    }

    const std::regex wallet_hint_pattern(
        R"((?:wallet|address|btc|bitcoin|eth|ethereum|xmr|monero)[_ -]?[A-Za-z0-9]{8,80})",
        std::regex::icase);
    for (std::sregex_iterator it(text.begin(), text.end(), wallet_hint_pattern), end; it != end; ++it) {
        addIoc(
            out,
            seen,
            "CRYPTO_WALLET_PATTERN",
            trimTrailingPunctuation(it->str()),
            0.55f,
            text,
            artifact.file_offset,
            static_cast<size_t>(it->position()));
    }

    const std::regex domain_pattern(R"(\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b)");
    for (std::sregex_iterator it(text.begin(), text.end(), domain_pattern), end; it != end; ++it) {
        const std::string value = trimTrailingPunctuation(it->str());
        if (!hasValidTld(value) || isLegitimateDomain(value)) {
            continue;
        }

        const double dga_score = scoreDgaDomain(value);
        if (dga_score >= 0.70) {
            addIoc(
                out,
                seen,
                "C2_DGA_DOMAIN",
                value,
                static_cast<float>(std::min(0.98, 0.55 + dga_score * 0.4)),
                text,
                artifact.file_offset,
                static_cast<size_t>(it->position()));
        }
    }
}

void IOCExtractor::addIoc(
    std::vector<IOC>& out,
    std::set<std::string>& seen,
    const std::string& type,
    const std::string& value,
    float confidence,
    const std::string& source,
    int base_offset,
    size_t match_offset) const {
    if (value.empty() || isFalsePositive(type, value)) {
        return;
    }

    const std::string key = type + ":" + normalizeLower(value);
    if (!seen.insert(key).second) {
        return;
    }

    const int file_offset = base_offset >= 0
        ? base_offset + static_cast<int>(match_offset)
        : -1;

    out.push_back({
        type,
        value,
        std::clamp(confidence, 0.0f, 1.0f),
        makeContext(source, match_offset, value.size()),
        file_offset
    });
}

bool IOCExtractor::isFalsePositive(const std::string& type, const std::string& value) const {
    const std::string lower = normalizeLower(value);
    static const std::set<std::string> generic_values = {
        "example.com", "example.org", "example.net", "localhost", "test.com",
        "yourdomain.com", "domain.com", "email.com", "user@example.com"
    };

    if (generic_values.find(lower) != generic_values.end()) {
        return true;
    }
    if ((type == "DOMAIN" || type == "C2_DGA_DOMAIN" || type == "ONION") && isLegitimateDomain(lower)) {
        return true;
    }
    if (type == "EMAIL" && lower.find("@example.") != std::string::npos) {
        return true;
    }
    if ((type == "API_KEY" || type == "HARDCODED_PASSWORD") && lower.find("placeholder") != std::string::npos) {
        return true;
    }
    return false;
}

bool IOCExtractor::isLegitimateDomain(const std::string& domain) const {
    const std::string lower = normalizeLower(domain);
    for (const auto& known : known_legitimate_domains) {
        if (lower == known || (lower.size() > known.size()
            && lower.compare(lower.size() - known.size(), known.size(), known) == 0
            && lower[lower.size() - known.size() - 1] == '.')) {
            return true;
        }
    }
    return false;
}

bool IOCExtractor::hasValidTld(const std::string& domain) const {
    const std::string lower = normalizeLower(domain);
    const size_t dot = lower.find_last_of('.');
    if (dot == std::string::npos || dot + 1 >= lower.size()) {
        return false;
    }
    return valid_tlds.find(lower.substr(dot + 1)) != valid_tlds.end();
}

bool IOCExtractor::isExcludedIpv4(const std::string& value) {
    std::vector<int> octets;
    std::stringstream stream(value);
    std::string token;
    while (std::getline(stream, token, '.')) {
        if (token.empty() || token.size() > 3 || !std::all_of(token.begin(), token.end(), [](unsigned char ch) {
            return std::isdigit(ch) != 0;
        })) {
            return true;
        }
        const int octet = std::stoi(token);
        if (octet < 0 || octet > 255) {
            return true;
        }
        octets.push_back(octet);
    }

    if (octets.size() != 4) {
        return true;
    }

    return octets[0] == 127
        || (octets[0] == 0 && octets[1] == 0)
        || octets[0] == 255
        || value == "0.0.0.0";
}

bool IOCExtractor::isLikelyPassword(const std::string& candidate) {
    if (candidate.size() < 8 || candidate.size() > 128) {
        return false;
    }

    bool has_upper = false;
    bool has_lower = false;
    bool has_digit = false;
    bool has_symbol = false;
    for (unsigned char ch : candidate) {
        has_upper = has_upper || std::isupper(ch);
        has_lower = has_lower || std::islower(ch);
        has_digit = has_digit || std::isdigit(ch);
        has_symbol = has_symbol || (!std::isalnum(ch));
    }

    const int classes = static_cast<int>(has_upper)
        + static_cast<int>(has_lower)
        + static_cast<int>(has_digit)
        + static_cast<int>(has_symbol);

    return classes >= 3 || shannonEntropy(candidate) >= 3.2;
}

double IOCExtractor::scoreDgaDomain(const std::string& domain) {
    const std::vector<std::string> labels = splitLabels(normalizeLower(domain));
    if (labels.empty()) {
        return 0.0;
    }

    std::string sld = labels.size() >= 2 ? labels[labels.size() - 2] : labels.front();
    sld.erase(std::remove(sld.begin(), sld.end(), '-'), sld.end());
    if (sld.size() <= 12) {
        return 0.0;
    }

    int vowels = 0;
    int consonants = 0;
    int digits = 0;
    int transitions = 0;
    char previous_class = 0;

    for (char ch : sld) {
        char current_class = 'o';
        if (std::isdigit(static_cast<unsigned char>(ch))) {
            ++digits;
            current_class = 'd';
        } else if (std::isalpha(static_cast<unsigned char>(ch))) {
            const bool vowel = std::string("aeiou").find(ch) != std::string::npos;
            if (vowel) {
                ++vowels;
                current_class = 'v';
            } else {
                ++consonants;
                current_class = 'c';
            }
        }

        if (previous_class != 0 && current_class != previous_class) {
            ++transitions;
        }
        previous_class = current_class;
    }

    const double length = static_cast<double>(sld.size());
    const double consonant_ratio = consonants / length;
    const double digit_ratio = digits / length;
    const double entropy = shannonEntropy(sld) / 4.7;
    const double transition_ratio = transitions / std::max(1.0, length - 1.0);
    const double low_vowel_penalty = vowels == 0 ? 0.18 : 0.0;
    const double hex_penalty = isHexString(sld) ? 0.10 : 0.0;

    double score = 0.0;
    score += std::max(0.0, consonant_ratio - 0.55) * 1.4;
    score += std::min(0.25, digit_ratio * 0.8);
    score += std::clamp(entropy - 0.62, 0.0, 0.35);
    score += std::clamp(transition_ratio - 0.45, 0.0, 0.25);
    score += low_vowel_penalty;
    score -= hex_penalty;

    return std::clamp(score, 0.0, 1.0);
}

double IOCExtractor::shannonEntropy(const std::string& value) {
    if (value.empty()) {
        return 0.0;
    }

    std::array<size_t, 256> counts = {};
    for (unsigned char ch : value) {
        ++counts[ch];
    }

    double entropy = 0.0;
    const double length = static_cast<double>(value.size());
    for (size_t count : counts) {
        if (count == 0) {
            continue;
        }
        const double probability = static_cast<double>(count) / length;
        entropy -= probability * std::log2(probability);
    }
    return entropy;
}

std::string IOCExtractor::normalizeLower(const std::string& value) {
    std::string lower;
    lower.reserve(value.size());
    for (unsigned char ch : value) {
        lower.push_back(static_cast<char>(std::tolower(ch)));
    }
    return lower;
}

std::string IOCExtractor::trimTrailingPunctuation(const std::string& value) {
    std::string trimmed = value;
    while (!trimmed.empty()) {
        const char ch = trimmed.back();
        if (ch == '.' || ch == ',' || ch == ';' || ch == ':' || ch == ')' || ch == ']' || ch == '}') {
            trimmed.pop_back();
        } else {
            break;
        }
    }
    return trimmed;
}

std::string IOCExtractor::makeContext(const std::string& source, size_t match_offset, size_t match_length) {
    constexpr size_t context_radius = 32;
    const size_t start = match_offset > context_radius ? match_offset - context_radius : 0;
    const size_t end = std::min(source.size(), match_offset + match_length + context_radius);
    return source.substr(start, end - start);
}

std::string IOCExtractor::defang(const std::string& value) {
    std::string out = value;
    size_t pos = 0;
    while ((pos = out.find('.', pos)) != std::string::npos) {
        out.replace(pos, 1, "[.]");
        pos += 3;
    }
    pos = 0;
    while ((pos = out.find("http://", pos)) != std::string::npos) {
        out.replace(pos, 7, "hxxp://");
        pos += 7;
    }
    pos = 0;
    while ((pos = out.find("https://", pos)) != std::string::npos) {
        out.replace(pos, 8, "hxxps://");
        pos += 8;
    }
    return out;
}

nlohmann::json IOCExtractor::toJson(const std::vector<IOC>& iocs, bool defang_output) const {
    nlohmann::json items = nlohmann::json::array();
    for (const auto& ioc : iocs) {
        items.push_back({
            {"type", ioc.type},
            {"value", defang_output ? defang(ioc.value) : ioc.value},
            {"confidence", ioc.confidence},
            {"context", defang_output ? defang(ioc.context) : ioc.context},
            {"file_offset", ioc.file_offset}
        });
    }
    return items;
}

std::string IOCExtractor::toCsv(const std::vector<IOC>& iocs, bool defang_output) const {
    std::ostringstream csv;
    csv << "type,value,confidence,context,file_offset\n";
    for (const auto& ioc : iocs) {
        csv << csvEscape(ioc.type) << ","
            << csvEscape(defang_output ? defang(ioc.value) : ioc.value) << ","
            << std::fixed << std::setprecision(2) << ioc.confidence << ","
            << csvEscape(defang_output ? defang(ioc.context) : ioc.context) << ","
            << ioc.file_offset << "\n";
    }
    return csv.str();
}

nlohmann::json IOCExtractor::toStixBundle(const std::vector<IOC>& iocs, bool defang_output) const {
    nlohmann::json objects = nlohmann::json::array();
    for (const auto& ioc : iocs) {
        const std::string value = defang_output ? defang(ioc.value) : ioc.value;
        objects.push_back({
            {"type", "indicator"},
            {"spec_version", "2.1"},
            {"id", deterministicStixId(ioc)},
            {"name", ioc.type + ": " + value},
            {"pattern_type", "stix"},
            {"pattern", stixPattern(ioc, value)},
            {"confidence", static_cast<int>(std::clamp(ioc.confidence, 0.0f, 1.0f) * 100.0f)},
            {"valid_from", "1970-01-01T00:00:00Z"},
            {"labels", nlohmann::json::array({"malicious-activity"})},
            {"x_stas_ioc_type", ioc.type},
            {"x_stas_context", defang_output ? defang(ioc.context) : ioc.context},
            {"x_stas_file_offset", ioc.file_offset}
        });
    }

    return {
        {"type", "bundle"},
        {"id", "bundle--22222222-3333-4444-8555-666666666666"},
        {"spec_version", "2.1"},
        {"objects", objects}
    };
}

std::string IOCExtractor::csvEscape(const std::string& value) {
    std::string escaped = value;
    size_t pos = 0;
    while ((pos = escaped.find('"', pos)) != std::string::npos) {
        escaped.replace(pos, 1, "\"\"");
        pos += 2;
    }
    return "\"" + escaped + "\"";
}

std::string IOCExtractor::indicatorPatternType(const std::string& ioc_type) {
    if (ioc_type == "IPV4") return "ipv4-addr:value";
    if (ioc_type == "IPV6") return "ipv6-addr:value";
    if (ioc_type == "DOMAIN" || ioc_type == "ONION" || ioc_type == "C2_DGA_DOMAIN") return "domain-name:value";
    if (ioc_type == "URL" || ioc_type == "DISCORD_WEBHOOK") return "url:value";
    if (ioc_type == "EMAIL") return "email-addr:value";
    if (ioc_type == "WINDOWS_PATH") return "file:name";
    if (ioc_type == "BITCOIN" || ioc_type == "ETHEREUM" || ioc_type == "MONERO") return "cryptocurrency-transaction:address";
    return "artifact:payload_bin";
}

std::string IOCExtractor::stixPattern(const IOC& ioc, const std::string& value) {
    std::string escaped = value;
    size_t pos = 0;
    while ((pos = escaped.find('\\', pos)) != std::string::npos) {
        escaped.replace(pos, 1, "\\\\");
        pos += 2;
    }
    pos = 0;
    while ((pos = escaped.find('\'', pos)) != std::string::npos) {
        escaped.replace(pos, 1, "\\'");
        pos += 2;
    }
    return "[" + indicatorPatternType(ioc.type) + " = '" + escaped + "']";
}

std::string IOCExtractor::deterministicStixId(const IOC& ioc) {
    const uint64_t left_hash = fnv1a64(ioc.type + ":" + normalizeLower(ioc.value));
    const uint64_t right_hash = fnv1a64(ioc.context + ":" + std::to_string(ioc.file_offset));

    std::ostringstream stream;
    stream << std::hex << std::setfill('0')
           << "indicator--"
           << std::setw(8) << static_cast<unsigned int>((left_hash >> 32) & 0xffffffffu) << "-"
           << std::setw(4) << static_cast<unsigned int>((left_hash >> 16) & 0xffffu) << "-"
           << std::setw(4) << static_cast<unsigned int>(left_hash & 0xffffu) << "-"
           << std::setw(4) << static_cast<unsigned int>((right_hash >> 48) & 0xffffu) << "-"
           << std::setw(12) << static_cast<unsigned long long>(right_hash & 0xffffffffffffull);
    return stream.str();
}
