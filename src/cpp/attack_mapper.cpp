#include "attack_mapper.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
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

std::vector<std::string> readStringArray(const nlohmann::json& object, const char* key) {
    std::vector<std::string> values;
    if (!object.contains(key)) {
        return values;
    }

    if (!object.at(key).is_array()) {
        throw std::runtime_error(std::string("ATT&CK rule field must be an array: ") + key);
    }

    for (const auto& item : object.at(key)) {
        if (!item.is_string()) {
            throw std::runtime_error(std::string("ATT&CK rule field contains non-string item: ") + key);
        }
        values.push_back(item.get<std::string>());
    }
    return values;
}
}

ATTACKMapper::ATTACKMapper() = default;

bool ATTACKMapper::loadRulesFromFile(const std::string& rules_path) {
    std::ifstream input(rules_path);
    if (!input.is_open()) {
        return false;
    }

    nlohmann::json rules_json;
    input >> rules_json;
    loadRulesFromJson(rules_json);
    return true;
}

void ATTACKMapper::loadRulesFromJson(const nlohmann::json& rules_json) {
    const nlohmann::json* rules_array = &rules_json;
    if (rules_json.is_object() && rules_json.contains("rules")) {
        rules_array = &rules_json.at("rules");
    }

    if (!rules_array->is_array()) {
        throw std::runtime_error("ATT&CK rules JSON must be an array or an object with a rules array");
    }

    std::vector<ATTACKRule> parsed_rules;
    for (const auto& item : *rules_array) {
        ATTACKRule rule;
        rule.id = item.at("id").get<std::string>();
        rule.name = item.at("name").get<std::string>();
        rule.tactic = item.value("tactic", "");
        rule.confidence = item.value("confidence", 0.5f);
        rule.required_imports = readStringArray(item, "imports");
        rule.required_behaviors = readStringArray(item, "behaviors");

        if (rule.id.empty() || rule.name.empty()) {
            throw std::runtime_error("ATT&CK rule must include non-empty id and name");
        }
        if (rule.required_imports.empty() && rule.required_behaviors.empty()) {
            throw std::runtime_error("ATT&CK rule must include imports and/or behaviors");
        }

        parsed_rules.push_back(rule);
    }

    rules = std::move(parsed_rules);
}

void ATTACKMapper::setRules(const std::vector<ATTACKRule>& new_rules) {
    rules = new_rules;
}

std::vector<ATTACKTechnique> ATTACKMapper::mapTechniques(
    const std::vector<std::string>& imports,
    const std::vector<std::string>& behavioral_events) const {
    std::vector<std::string> normalized_imports;
    normalized_imports.reserve(imports.size());
    for (const auto& item : imports) {
        normalized_imports.push_back(normalize(item));
    }

    std::vector<std::string> normalized_behaviors;
    normalized_behaviors.reserve(behavioral_events.size());
    for (const auto& item : behavioral_events) {
        normalized_behaviors.push_back(normalize(item));
    }

    std::vector<ATTACKTechnique> techniques;
    for (const auto& rule : rules) {
        bool matched = true;
        std::vector<std::string> triggered_by;

        for (const auto& required_import : rule.required_imports) {
            if (!containsRequirement(normalized_imports, required_import)) {
                matched = false;
                break;
            }
            triggered_by.push_back("import:" + required_import);
        }

        if (!matched) {
            continue;
        }

        for (const auto& required_behavior : rule.required_behaviors) {
            if (!containsRequirement(normalized_behaviors, required_behavior)) {
                matched = false;
                break;
            }
            triggered_by.push_back("behavior:" + required_behavior);
        }

        if (!matched) {
            continue;
        }

        auto existing = std::find_if(techniques.begin(), techniques.end(),
            [&rule](const ATTACKTechnique& technique) {
                return technique.id == rule.id;
            });

        if (existing == techniques.end()) {
            techniques.push_back({
                rule.id,
                rule.name,
                rule.tactic,
                rule.confidence,
                triggered_by
            });
        } else if (rule.confidence > existing->confidence) {
            existing->name = rule.name;
            existing->tactic = rule.tactic;
            existing->confidence = rule.confidence;
            existing->triggered_by = triggered_by;
        } else if (rule.confidence == existing->confidence) {
            existing->triggered_by.insert(
                existing->triggered_by.end(),
                triggered_by.begin(),
                triggered_by.end());
        }
    }

    for (auto& technique : techniques) {
        std::sort(technique.triggered_by.begin(), technique.triggered_by.end());
        technique.triggered_by.erase(
            std::unique(technique.triggered_by.begin(), technique.triggered_by.end()),
            technique.triggered_by.end());
    }

    std::sort(techniques.begin(), techniques.end(),
        [](const ATTACKTechnique& left, const ATTACKTechnique& right) {
            if (left.confidence != right.confidence) {
                return left.confidence > right.confidence;
            }
            return left.id < right.id;
        });

    return techniques;
}

nlohmann::json ATTACKMapper::toStixBundle(const std::vector<ATTACKTechnique>& techniques) const {
    nlohmann::json objects = nlohmann::json::array();
    for (const auto& technique : techniques) {
        objects.push_back(techniqueToStix(technique));
    }

    return {
        {"type", "bundle"},
        {"id", "bundle--11111111-2222-4333-8444-555555555555"},
        {"spec_version", "2.1"},
        {"objects", objects}
    };
}

nlohmann::json ATTACKMapper::techniqueToStix(const ATTACKTechnique& technique) const {
    nlohmann::json kill_chain_phases = nlohmann::json::array();
    if (!technique.tactic.empty()) {
        kill_chain_phases.push_back({
            {"kill_chain_name", "mitre-attack"},
            {"phase_name", tacticToPhaseName(technique.tactic)}
        });
    }

    return {
        {"type", "attack-pattern"},
        {"spec_version", "2.1"},
        {"id", makeDeterministicStixId(technique)},
        {"name", technique.name},
        {"external_references", nlohmann::json::array({
            {
                {"source_name", "mitre-attack"},
                {"external_id", technique.id},
                {"url", "https://attack.mitre.org/techniques/" + techniqueUrlPath(technique.id)}
            }
        })},
        {"kill_chain_phases", kill_chain_phases},
        {"confidence", static_cast<int>(std::clamp(technique.confidence, 0.0f, 1.0f) * 100.0f)},
        {"x_stas_attack_id", technique.id},
        {"x_stas_tactic", technique.tactic},
        {"x_stas_confidence", technique.confidence},
        {"x_stas_triggered_by", technique.triggered_by}
    };
}

std::string ATTACKMapper::normalize(const std::string& value) {
    std::string normalized;
    normalized.reserve(value.size());
    for (char ch : value) {
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return normalized;
}

bool ATTACKMapper::matchesPattern(const std::string& value, const std::string& pattern) {
    const std::string normalized_pattern = normalize(pattern);
    if (normalized_pattern.empty()) {
        return value.empty();
    }

    if (normalized_pattern == "*") {
        return true;
    }

    const bool starts_with_wildcard = normalized_pattern.front() == '*';
    const bool ends_with_wildcard = normalized_pattern.back() == '*';
    std::string token = normalized_pattern;
    token.erase(std::remove(token.begin(), token.end(), '*'), token.end());

    if (starts_with_wildcard && ends_with_wildcard) {
        return value.find(token) != std::string::npos;
    }
    if (starts_with_wildcard) {
        return value.size() >= token.size()
            && value.compare(value.size() - token.size(), token.size(), token) == 0;
    }
    if (ends_with_wildcard) {
        return value.size() >= token.size()
            && value.compare(0, token.size(), token) == 0;
    }

    return value == normalized_pattern;
}

bool ATTACKMapper::containsRequirement(
    const std::vector<std::string>& normalized_values,
    const std::string& requirement) {
    for (const auto& value : normalized_values) {
        if (matchesPattern(value, requirement)) {
            return true;
        }
    }
    return false;
}

std::string ATTACKMapper::tacticToPhaseName(const std::string& tactic) {
    std::string phase = normalize(tactic);
    for (char& ch : phase) {
        if (ch == ' ' || ch == '_') {
            ch = '-';
        }
    }
    return phase;
}

std::string ATTACKMapper::techniqueUrlPath(const std::string& attack_id) {
    std::string path = attack_id;
    std::replace(path.begin(), path.end(), '.', '/');
    return path;
}

std::string ATTACKMapper::makeDeterministicStixId(const ATTACKTechnique& technique) {
    const uint64_t left_hash = fnv1a64("stas:" + technique.id);
    const uint64_t right_hash = fnv1a64(technique.name + ":" + technique.tactic);

    std::ostringstream stream;
    stream << std::hex << std::setfill('0')
           << "attack-pattern--"
           << std::setw(8) << static_cast<unsigned int>((left_hash >> 32) & 0xffffffffu) << "-"
           << std::setw(4) << static_cast<unsigned int>((left_hash >> 16) & 0xffffu) << "-"
           << std::setw(4) << static_cast<unsigned int>(left_hash & 0xffffu) << "-"
           << std::setw(4) << static_cast<unsigned int>((right_hash >> 48) & 0xffffu) << "-"
           << std::setw(12) << static_cast<unsigned long long>(right_hash & 0xffffffffffffull);
    return stream.str();
}
