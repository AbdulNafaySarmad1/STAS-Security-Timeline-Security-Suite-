#include "import_profiler.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <utility>

namespace {
std::vector<std::string> readStringArray(const nlohmann::json& object, const char* key) {
    std::vector<std::string> values;
    if (!object.contains(key)) {
        return values;
    }
    if (!object.at(key).is_array()) {
        throw std::runtime_error(std::string("Import profiler field must be an array: ") + key);
    }

    for (const auto& item : object.at(key)) {
        if (!item.is_string()) {
            throw std::runtime_error(std::string("Import profiler field contains non-string item: ") + key);
        }
        values.push_back(item.get<std::string>());
    }
    return values;
}
}

ImportProfiler::ImportProfiler() = default;

bool ImportProfiler::loadRulesFromFile(const std::string& rules_path) {
    std::ifstream input(rules_path);
    if (!input.is_open()) {
        return false;
    }

    nlohmann::json rules_json;
    input >> rules_json;
    loadRulesFromJson(rules_json);
    return true;
}

void ImportProfiler::loadRulesFromJson(const nlohmann::json& rules_json) {
    if (!rules_json.is_object()) {
        throw std::runtime_error("Import capability rules JSON must be an object");
    }

    const auto& categories_json = rules_json.at("categories");
    const auto& predictions_json = rules_json.at("behavior_predictions");
    if (!categories_json.is_array() || !predictions_json.is_array()) {
        throw std::runtime_error("Import rules require categories and behavior_predictions arrays");
    }

    std::vector<CapabilityRule> parsed_capabilities;
    for (const auto& item : categories_json) {
        CapabilityRule rule;
        rule.category = item.at("category").get<std::string>();
        rule.imports = readStringArray(item, "imports");
        rule.risk_contribution = std::clamp(item.value("risk_contribution", 0), 0, 10);

        if (rule.category.empty() || rule.imports.empty()) {
            throw std::runtime_error("Each import capability category requires category and imports");
        }

        parsed_capabilities.push_back(rule);
    }

    std::vector<BehaviorPredictionRule> parsed_predictions;
    for (const auto& item : predictions_json) {
        BehaviorPredictionRule rule;
        rule.required_categories = readStringArray(item, "required_categories");
        rule.prediction = item.at("prediction").get<std::string>();
        rule.priority = item.value("priority", 0);

        if (rule.required_categories.empty() || rule.prediction.empty()) {
            throw std::runtime_error("Each behavior prediction requires required_categories and prediction");
        }

        parsed_predictions.push_back(rule);
    }

    capability_rules = std::move(parsed_capabilities);
    prediction_rules = std::move(parsed_predictions);
}

void ImportProfiler::setRules(
    const std::vector<CapabilityRule>& new_capability_rules,
    const std::vector<BehaviorPredictionRule>& new_prediction_rules) {
    capability_rules = new_capability_rules;
    prediction_rules = new_prediction_rules;
}

ImportProfile ImportProfiler::profileImports(const std::vector<std::string>& imports) const {
    std::vector<std::string> normalized_imports;
    normalized_imports.reserve(imports.size() * 2);
    for (const auto& item : imports) {
        normalized_imports.push_back(normalize(item));
        normalized_imports.push_back(baseImportName(item));
    }

    std::sort(normalized_imports.begin(), normalized_imports.end());
    normalized_imports.erase(
        std::unique(normalized_imports.begin(), normalized_imports.end()),
        normalized_imports.end());

    ImportProfile profile;
    profile.stealth_score = 0;

    for (const auto& rule : capability_rules) {
        CategoryProfile detail;
        detail.import_count = 0;
        detail.risk_contribution = rule.risk_contribution;

        for (const auto& wanted_import : rule.imports) {
            if (containsImport(normalized_imports, wanted_import)) {
                detail.matched_imports.push_back(wanted_import);
            }
        }

        std::sort(detail.matched_imports.begin(), detail.matched_imports.end());
        detail.matched_imports.erase(
            std::unique(detail.matched_imports.begin(), detail.matched_imports.end()),
            detail.matched_imports.end());
        detail.import_count = static_cast<int>(detail.matched_imports.size());

        if (detail.import_count > 0) {
            profile.categories[rule.category] = detail.matched_imports;
            profile.category_details[rule.category] = detail;
        }
    }

    profile.behavior_prediction = predictBehavior(profile.category_details, prediction_rules);
    profile.top_capabilities = calculateTopCapabilities(profile.category_details);
    profile.stealth_score = calculateStealthScore(profile.category_details);
    return profile;
}

nlohmann::json ImportProfiler::toJson(const ImportProfile& profile) const {
    nlohmann::json category_details_json = nlohmann::json::object();
    for (const auto& item : profile.category_details) {
        category_details_json[item.first] = {
            {"import_count", item.second.import_count},
            {"matched_imports", item.second.matched_imports},
            {"risk_contribution", item.second.risk_contribution}
        };
    }

    return {
        {"categories", profile.categories},
        {"category_details", category_details_json},
        {"behavior_prediction", profile.behavior_prediction},
        {"top_capabilities", profile.top_capabilities},
        {"stealth_score", profile.stealth_score}
    };
}

std::string ImportProfiler::normalize(const std::string& value) {
    std::string normalized;
    normalized.reserve(value.size());
    for (char ch : value) {
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return normalized;
}

std::string ImportProfiler::baseImportName(const std::string& value) {
    std::string normalized = normalize(value);

    const size_t bang = normalized.find_last_of('!');
    if (bang != std::string::npos && bang + 1 < normalized.size()) {
        normalized = normalized.substr(bang + 1);
    }

    const size_t dot = normalized.find_last_of('.');
    if (dot != std::string::npos && dot + 1 < normalized.size()) {
        const std::string extension = normalized.substr(dot + 1);
        if (extension == "dll" || extension == "exe") {
            return normalized;
        }
        normalized = normalized.substr(dot + 1);
    }

    if (normalized.size() > 1) {
        const char suffix = normalized.back();
        if ((suffix == 'a' || suffix == 'w') && std::isalpha(static_cast<unsigned char>(normalized[normalized.size() - 2]))) {
            normalized.pop_back();
        }
    }

    return normalized;
}

bool ImportProfiler::containsImport(
    const std::vector<std::string>& normalized_imports,
    const std::string& wanted_import) {
    const std::string wanted = baseImportName(wanted_import);
    return std::binary_search(normalized_imports.begin(), normalized_imports.end(), wanted)
        || std::binary_search(normalized_imports.begin(), normalized_imports.end(), normalize(wanted_import));
}

std::string ImportProfiler::predictBehavior(
    const std::map<std::string, CategoryProfile>& category_details,
    const std::vector<BehaviorPredictionRule>& prediction_rules) {
    const BehaviorPredictionRule* best_rule = nullptr;

    for (const auto& rule : prediction_rules) {
        bool matched = true;
        for (const auto& category : rule.required_categories) {
            if (category_details.find(category) == category_details.end()) {
                matched = false;
                break;
            }
        }

        if (!matched) {
            continue;
        }

        if (best_rule == nullptr
            || rule.priority > best_rule->priority
            || (rule.priority == best_rule->priority
                && rule.required_categories.size() > best_rule->required_categories.size())) {
            best_rule = &rule;
        }
    }

    if (best_rule != nullptr) {
        return best_rule->prediction;
    }

    if (!category_details.empty()) {
        return "Potentially suspicious capabilities detected from imported APIs";
    }

    return "No strong behavior prediction from imports";
}

std::vector<std::string> ImportProfiler::calculateTopCapabilities(
    const std::map<std::string, CategoryProfile>& category_details) {
    std::vector<std::pair<std::string, CategoryProfile>> ranked(
        category_details.begin(),
        category_details.end());

    std::sort(ranked.begin(), ranked.end(),
        [](const auto& left, const auto& right) {
            if (left.second.risk_contribution != right.second.risk_contribution) {
                return left.second.risk_contribution > right.second.risk_contribution;
            }
            if (left.second.import_count != right.second.import_count) {
                return left.second.import_count > right.second.import_count;
            }
            return left.first < right.first;
        });

    std::vector<std::string> capabilities;
    for (const auto& item : ranked) {
        capabilities.push_back(item.first);
        if (capabilities.size() == 5) {
            break;
        }
    }
    return capabilities;
}

int ImportProfiler::calculateStealthScore(
    const std::map<std::string, CategoryProfile>& category_details) {
    int score = 0;

    for (const auto& item : category_details) {
        const std::string& category = item.first;
        const CategoryProfile& detail = item.second;
        score += detail.risk_contribution;

        if (category == "EVASION") {
            score += 20;
        } else if (category == "PROCESS_INJECTION") {
            score += 15;
        } else if (category == "MEMORY") {
            score += 8;
        } else if (category == "CRYPTO") {
            score += 6;
        }

        if (detail.import_count >= 3) {
            score += 5;
        }
    }

    if (category_details.find("EVASION") != category_details.end()
        && category_details.find("PROCESS_INJECTION") != category_details.end()) {
        score += 15;
    }

    if (category_details.find("MEMORY") != category_details.end()
        && category_details.find("PROCESS_INJECTION") != category_details.end()) {
        score += 10;
    }

    return std::clamp(score, 0, 100);
}
