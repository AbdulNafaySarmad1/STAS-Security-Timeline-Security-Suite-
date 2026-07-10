#include "static_analysis.h"
#include "pe_structs.h"

#ifdef STAS_WITH_YARA
#include <yara.h>
#endif

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>

StaticAnalysis::StaticAnalysis(const std::string& file)
    : filepath(file), overall_packed_confidence(0) {}

void StaticAnalysis::performAnalysis() {
    // Hashing
    computeHashes();

    // Entropy
    calculateEntropy();

    // Imports/Exports (use PE parser like pe-parse lib or custom)
    // ...

    // YARA
#ifdef STAS_WITH_YARA
    yr_initialize();
    // Load rules and scan
    yr_finalize();
#endif

    // Packers detection (signature-based)
    detectPackers();
}

void StaticAnalysis::computeHashes() {
    // MD5, SHA1, SHA256 implementation using OpenSSL
    // Read file, compute digests
}

void StaticAnalysis::calculateEntropy() {
    section_entropies.clear();
    overall_packed_confidence = 0;

    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open sample for PE section entropy analysis: " + filepath);
    }

    const std::streamsize file_size = file.tellg();
    if (file_size <= 0) {
        throw std::runtime_error("Sample is empty: " + filepath);
    }

    std::vector<unsigned char> buffer(static_cast<size_t>(file_size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), file_size)) {
        throw std::runtime_error("Failed to read sample for PE section entropy analysis: " + filepath);
    }

    if (buffer.size() < sizeof(StasImageDosHeader)) {
        throw std::runtime_error("File too small for DOS header: " + filepath);
    }

    const auto* dos_header = reinterpret_cast<const StasImageDosHeader*>(buffer.data());
    if (dos_header->e_magic != STAS_IMAGE_DOS_SIGNATURE) {
        throw std::runtime_error("Invalid DOS signature; not a PE file: " + filepath);
    }

    if (dos_header->e_lfanew < 0) {
        throw std::runtime_error("Invalid negative PE header offset: " + filepath);
    }

    const size_t nt_header_offset = static_cast<size_t>(dos_header->e_lfanew);
    const size_t minimum_nt_header_size = sizeof(std::uint32_t) + sizeof(StasImageFileHeader);
    if (nt_header_offset > buffer.size()
        || minimum_nt_header_size > buffer.size() - nt_header_offset) {
        throw std::runtime_error("Invalid PE header offset: " + filepath);
    }

    std::uint32_t pe_signature = 0;
    std::memcpy(&pe_signature, buffer.data() + nt_header_offset, sizeof(pe_signature));
    if (pe_signature != STAS_IMAGE_NT_SIGNATURE) {
        throw std::runtime_error("Invalid NT signature; not a PE file: " + filepath);
    }

    const auto* file_header = reinterpret_cast<const StasImageFileHeader*>(
        buffer.data() + nt_header_offset + sizeof(std::uint32_t));
    const size_t optional_header_offset =
        nt_header_offset + sizeof(std::uint32_t) + sizeof(StasImageFileHeader);
    if (optional_header_offset > buffer.size()
        || file_header->SizeOfOptionalHeader > buffer.size() - optional_header_offset) {
        throw std::runtime_error("PE optional header extends beyond file bounds: " + filepath);
    }

    const size_t section_table_offset =
        optional_header_offset
        + file_header->SizeOfOptionalHeader;

    const size_t section_table_size =
        static_cast<size_t>(file_header->NumberOfSections) * sizeof(StasImageSectionHeader);
    if (section_table_offset > buffer.size()
        || section_table_size > buffer.size() - section_table_offset) {
        throw std::runtime_error("PE section table extends beyond file bounds: " + filepath);
    }

    const auto* section_header = reinterpret_cast<const StasImageSectionHeader*>(
        buffer.data() + section_table_offset);

    for (std::uint16_t index = 0; index < file_header->NumberOfSections; ++index) {
        const StasImageSectionHeader& section = section_header[index];

        char section_name[STAS_IMAGE_SIZEOF_SHORT_NAME + 1] = {};
        std::copy(
            section.Name,
            section.Name + STAS_IMAGE_SIZEOF_SHORT_NAME,
            reinterpret_cast<unsigned char*>(section_name));

        const std::uint32_t raw_offset = section.PointerToRawData;
        const std::uint32_t raw_size = section.SizeOfRawData;
        double entropy = 0.0;

        if (raw_size > 0 && raw_offset < buffer.size()) {
            const size_t available = buffer.size() - raw_offset;
            const size_t bounded_size = std::min<size_t>(raw_size, available);
            entropy = calculateShannonEntropy(buffer.data() + raw_offset, bounded_size);
        }

        section_entropies.push_back(interpretSectionEntropy(section_name, entropy));
    }

    overall_packed_confidence = calculatePackedConfidence(section_entropies);

    for (const auto& section : section_entropies) {
        std::cout << "Section " << section.name
                  << " entropy=" << section.entropy
                  << " verdict=" << section.verdict
                  << " suspicious=" << (section.suspicious ? "true" : "false")
                  << " explanation=" << section.explanation
                  << std::endl;
    }
    std::cout << "Overall packed confidence: "
              << overall_packed_confidence << "/100" << std::endl;
}

void StaticAnalysis::detectPackers() {
    // Check for UPX etc. signatures
}

const std::vector<std::string>& StaticAnalysis::getImportedFunctions() const {
    return imported_functions;
}

const std::vector<SectionEntropy>& StaticAnalysis::getSectionEntropies() const {
    return section_entropies;
}

int StaticAnalysis::getOverallPackedConfidence() const {
    return overall_packed_confidence;
}

double StaticAnalysis::calculateShannonEntropy(const unsigned char* data, size_t size) {
    if (data == nullptr || size == 0) {
        return 0.0;
    }

    std::array<size_t, 256> frequencies = {};
    for (size_t i = 0; i < size; ++i) {
        ++frequencies[data[i]];
    }

    double entropy = 0.0;
    const double length = static_cast<double>(size);
    for (size_t count : frequencies) {
        if (count == 0) {
            continue;
        }

        const double probability = static_cast<double>(count) / length;
        entropy -= probability * std::log2(probability);
    }

    return entropy;
}

SectionEntropy StaticAnalysis::interpretSectionEntropy(const std::string& name, double entropy) {
    SectionEntropy result;
    result.name = name.empty() ? "<unnamed>" : name;
    result.entropy = entropy;
    result.suspicious = entropy > 7.2 || entropy == 0.0;

    if (entropy == 0.0) {
        result.verdict = "suspicious";
        result.explanation = "Empty or zeroed section - suspicious padding";
        return result;
    }

    if (entropy > 7.2) {
        result.verdict = "suspicious";
    } else if (entropy < 6.0) {
        result.verdict = "normal";
    } else {
        result.verdict = "borderline";
    }

    if (result.name == ".text" && entropy > 7.0) {
        result.explanation = "Code section appears packed or encrypted - possible runtime unpacking";
    } else if (result.name == ".rsrc" && entropy > 7.5) {
        result.explanation = "Resource section highly compressed - possible dropper";
    } else if (result.verdict == "suspicious") {
        result.explanation = "High entropy section - likely packed, encrypted, or compressed data";
    } else if (result.verdict == "borderline") {
        result.explanation = "Moderate entropy section - review alongside imports, strings, and packer indicators";
    } else {
        result.explanation = "Entropy is within the expected range for this section";
    }

    if ((result.name == ".text" && entropy > 7.0) || (result.name == ".rsrc" && entropy > 7.5)) {
        result.suspicious = true;
    }

    return result;
}

int StaticAnalysis::calculatePackedConfidence(const std::vector<SectionEntropy>& sections) {
    if (sections.empty()) {
        return 0;
    }

    int score = 0;
    int suspicious_sections = 0;
    int borderline_sections = 0;

    for (const auto& section : sections) {
        if (section.entropy == 0.0) {
            score += 10;
        }

        if (section.entropy > 7.5) {
            score += 30;
        } else if (section.entropy > 7.2) {
            score += 22;
        } else if (section.entropy >= 6.0) {
            score += 8;
            ++borderline_sections;
        }

        if (section.name == ".text" && section.entropy > 7.0) {
            score += 25;
        }

        if (section.name == ".rsrc" && section.entropy > 7.5) {
            score += 20;
        }

        if (section.suspicious) {
            ++suspicious_sections;
        }
    }

    if (suspicious_sections >= 2) {
        score += 15;
    }
    if (borderline_sections >= 3) {
        score += 10;
    }

    return std::clamp(score, 0, 100);
}
