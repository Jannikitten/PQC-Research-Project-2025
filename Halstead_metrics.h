#ifndef HALSTEAD_METRICS_H
#define HALSTEAD_METRICS_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <algorithm>
#include <cmath>
#include <iomanip>

namespace Halstead {

// --- Configuration: Operators and Keywords (C++23) ---
inline std::vector<std::string> get_cpp23_operators_and_keywords() {
    std::vector<std::string> ops_and_keywords = {
        // Three-character operators
        "<<=", ">>=", "<=>", "...", "->*",
        // Two-character operators
        "::", "++", "--", "->", ".*",
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>",
        "==", "!=", "<=", ">=", "&&", "||",
        "##", // Token pasting (preprocessor, but might appear)
        // Single-character operators (common)
        "+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "=", "<", ">",
        "?", ":", ";", ",", ".", "(", ")", "[", "]", "{", "}",
        // Keywords often treated as operators
        "alignas", "alignof", "asm", "auto", "bool", "break", "case", "catch", "char",
        "char8_t", "char16_t", "char32_t", "class", "compl", "concept", "const",
        "consteval", "constexpr", "constinit", "const_cast", "continue", "co_await",
        "co_return", "co_yield", "decltype", "default", "delete", "do", "double",
        "dynamic_cast", "else", "enum", "explicit", "export", "extern", "false",
        "float", "for", "friend", "goto", "if", "inline", "int", "long", "module",
        "mutable", "namespace", "new", "noexcept", "nullptr", "operator", "private",
        "protected", "public", "reflexpr", "register", "reinterpret_cast", "requires",
        "return", "short", "signed", "sizeof", "static", "static_assert",
        "static_cast", "struct", "switch", "synchronized", "template", "this",
        "thread_local", "throw", "true", "try", "typedef", "typeid", "typename",
        "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t",
        "while",
    };

    std::sort(ops_and_keywords.begin(), ops_and_keywords.end(), [](const std::string& a, const std::string& b) {
        return b.length() < a.length();
    });
    return ops_and_keywords;
}

// --- Helper Functions ---
inline std::string remove_comments(const std::string& code) {
    std::string result;
    result.reserve(code.length());
    bool in_multiline_comment = false;
    bool in_single_line_comment = false;
    bool in_string_literal = false;
    bool in_char_literal = false;
    char prev_char = 0;

    for (size_t i = 0; i < code.length(); ++i) {
        char current_char = code[i];
        char next_char = (i + 1 < code.length()) ? code[i+1] : 0;

        if (in_single_line_comment) {
            if (current_char == '\n') {
                in_single_line_comment = false;
                result += current_char;
            }
            prev_char = current_char;
            continue;
        }

        if (in_multiline_comment) {
            if (current_char == '*' && next_char == '/') {
                in_multiline_comment = false;
                i++;
            }
            prev_char = current_char;
            continue;
        }

        if (in_string_literal) {
            result += current_char;
            if (current_char == '"' && prev_char != '\\') {
                 in_string_literal = false;
            } else if (current_char == '\\' && prev_char == '\\') {
                 prev_char = 0;
            } else {
                prev_char = current_char;
            }
            continue;
        }

        if (in_char_literal) {
            result += current_char;
             if (current_char == '\'' && prev_char != '\\') {
                in_char_literal = false;
            } else if (current_char == '\\' && prev_char == '\\') {
                 prev_char = 0;
            } else {
                prev_char = current_char;
            }
            continue;
        }

        // Check for comment starts
        if (current_char == '/' && next_char == '/') {
            in_single_line_comment = true;
            i++;
            prev_char = next_char;
            continue;
        }
        if (current_char == '/' && next_char == '*') {
            in_multiline_comment = true;
            i++;
            prev_char = next_char;
            continue;
        }

        if (current_char == '"') {
            if (!( (i >= 1 && code[i-1] == 'R') ||
                   (i >= 2 && (code[i-2] == 'L' || code[i-2] == 'u' || code[i-2] == 'U') && code[i-1] == 'R') ||
                   (i >= 3 && code[i-3] == 'u' && code[i-2] == '8' && code[i-1] == 'R') )) {
                in_string_literal = true;
            }
        } else if (current_char == '\'') {
            in_char_literal = true;
        }
        result += current_char;
        prev_char = current_char;
    }
    return result;
}

// --- Halstead Metrics Data Structure ---
struct HalsteadReport {
    bool success = false;
    std::string error_message;

    int n1 = 0; // Distinct Operators
    int N1 = 0; // Total Operators
    int n2 = 0; // Distinct Operands
    int N2 = 0; // Total Operands

    double vocabulary = 0;
    double length = 0;
    double volume = 0;
    double difficulty = 0;
    double level = 0;
    double effort = 0;
    double time_to_program = 0;
    double bugs_delivered = 0;

    std::set<std::string> distinct_operators_set;
    std::map<std::string, int> operator_token_counts;
    std::set<std::string> distinct_operands_set;
    std::map<std::string, int> operand_token_counts;
};


// --- Tokenizer and Metric Calculation Class ---
class HalsteadMetricsCalculator {
public:
    HalsteadMetricsCalculator() : cpp_ops_and_keywords(get_cpp23_operators_and_keywords()) {}

    bool calculate_metrics_from_file_content(const std::string& filepath, HalsteadReport& report) {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            report.success = false;
            report.error_message = "Error: Could not open file: " + filepath;
            return false;
        }

        std::string code_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        std::string processed_code = remove_comments(code_content);

        internal_operator_counts.clear();
        internal_operand_counts.clear();

        int current_N1 = 0;
        int current_n1 = 0;
        int current_N2 = 0;
        int current_n2 = 0;
        std::set<std::string> current_distinct_operators;
        std::set<std::string> current_distinct_operands;


        tokenize_and_count(processed_code, current_distinct_operators, current_distinct_operands);

        for (const auto& pair : internal_operator_counts) {
            if (pair.second > 0) {
                current_N1 += pair.second;
            }
        }
        current_n1 = current_distinct_operators.size();

        for (const auto& pair : internal_operand_counts) {
            if (pair.second > 0) {
                current_N2 += pair.second;
            }
        }
        current_n2 = current_distinct_operands.size();

        report.n1 = current_n1;
        report.N1 = current_N1;
        report.n2 = current_n2;
        report.N2 = current_N2;
        report.distinct_operators_set = current_distinct_operators;
        report.operator_token_counts = internal_operator_counts;
        report.distinct_operands_set = current_distinct_operands;
        report.operand_token_counts = internal_operand_counts;


        // Calculate Halstead values
        if (report.n1 == 0 && report.n2 == 0 && report.N1 == 0 && report.N2 == 0) {
            report.success = true;
            report.length = 0;
            report.vocabulary = 0;
            return true;
        }

        report.length = report.N1 + report.N2;
        report.vocabulary = report.n1 + report.n2;

        if (report.vocabulary > 0) { // log2(0) is undefined, log2(1) is 0
             report.volume = (report.vocabulary == 1) ? 0 : report.length * std::log2(report.vocabulary);
        } else {
            report.volume = 0;
        }

        if (report.n2 > 0) {
            report.difficulty = (static_cast<double>(report.n1) / 2.0) * (static_cast<double>(report.N2) / static_cast<double>(report.n2));
        } else {
            report.difficulty = (report.n1 > 0 && report.N2 > 0) ? 1e9 : 0;
        }

        if (report.difficulty > 1e-9) {
            report.level = 1.0 / report.difficulty;
        } else {
             // if n1=0, N2=0, difficulty is 0, level should be undefined or 0.
             // if n1>0 or N2>0 but n2=0 (making difficulty ~infinite or large), level should be ~0.
             // if difficulty is truly 0 (e.g. no operators), level is problematic.
            report.level = (report.difficulty < 1e-9 && (report.n1 > 0 || report.N2 > 0) ) ? 0 : // effectively 0 level if difficulty is massive
                           ( (report.n1 == 0 && report.N2 == 0) ? 0 : 1e9);
        }

        report.effort = report.volume * report.difficulty;
        report.time_to_program = report.effort / 18.0;
        report.bugs_delivered = report.volume / 3000.0;

        report.success = true;
        return true;
    }


private:
    // Member variables for token counts, distinct sets are passed by ref to tokenize_and_count
    std::map<std::string, int> internal_operator_counts;
    std::map<std::string, int> internal_operand_counts;

    // Store pre-sorted operators and regexes as members for efficiency
    const std::vector<std::string> cpp_ops_and_keywords;

    // Regexes are somewhat expensive to construct. Making them const members.
    const std::regex number_literal_regex{
        R"((0[xX][0-9a-fA-F]+(?:[ulUL]{0,2}|[lL]{1,2}|[zZ])?)|(0[bB][01]+(?:[ulUL]{0,2}|[lL]{1,2}|[zZ])?)|([0-7]+(?:[ulUL]{0,2}|[lL]{1,2}|[zZ])?)|([1-9][0-9]*(?:[ulUL]{0,2}|[lL]{1,2}|[zZ])?)|(0(?:[ulUL]{0,2}|[lL]{1,2}|[zZ])?)|([0-9]+\.[0-9]*(?:[eE][+-]?[0-9]+)?(?:[fFLl])?)|(\.[0-9]+(?:[eE][+-]?[0-9]+)?(?:[fFLl])?)|([0-9]+[eE][+-]?[0-9]+(?:[fFLl])?)|(0[xX][0-9a-fA-F]+\.[0-9a-fA-F]*(?:[pP][+-]?[0-9]+)?(?:[fFLl])?)|(0[xX]\.[0-9a-fA-F]+(?:[pP][+-]?[0-9]+)?(?:[fFLl])?)|(0[xX][0-9a-fA-F]+[pP][+-]?[0-9]+(?:[fFLl])?))"
    };
    const std::regex char_literal_regex{
        R"((?:L|u8|u|U)?\'(?:[^'\\]|\\['"?\\abfnrtv]|[\\0-7]{1,3}|\\x[0-9a-fA-F]+|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8})+\')"
    };
    const std::regex string_literal_regex{
      R"((?:L|u8|u|U)?(?:R"([^ ()\t\v\f\n]*)\((?:.|\n)*?\)\1"|"(?:[^"\\]|\\.)*"))"
  };
    const std::regex identifier_regex{
        R"([_a-zA-Z][_a-zA-Z0-9]*)"
    };


    void tokenize_and_count(const std::string& code,
                            std::set<std::string>& distinct_operators,
                            std::set<std::string>& distinct_operands) {
        size_t current_pos = 0;

        while (current_pos < code.length()) {
            while (current_pos < code.length() && std::isspace(code[current_pos])) {
                current_pos++;
            }
            if (current_pos >= code.length()) break;

            std::string current_substring = code.substr(current_pos);
            bool matched_token = false;

            for (const std::string& op_candidate : cpp_ops_and_keywords) {
                if (current_substring.rfind(op_candidate, 0) == 0) {
                    if (std::isalpha(op_candidate[0])) {
                        if (current_pos + op_candidate.length() < code.length() &&
                            (std::isalnum(code[current_pos + op_candidate.length()]) || code[current_pos + op_candidate.length()] == '_') ) {
                            continue;
                        }
                    }
                    internal_operator_counts[op_candidate]++;
                    distinct_operators.insert(op_candidate);
                    current_pos += op_candidate.length();
                    matched_token = true;
                    break;
                }
            }
            if (matched_token) continue;

            std::smatch match;

            if (std::regex_search(current_substring, match, string_literal_regex, std::regex_constants::match_continuous)) {
                internal_operand_counts[match.str()]++;
                distinct_operands.insert(match.str());
                current_pos += match.length();
                matched_token = true;
            }
            if (matched_token) continue;

            if (std::regex_search(current_substring, match, char_literal_regex, std::regex_constants::match_continuous)) {
                internal_operand_counts[match.str()]++;
                distinct_operands.insert(match.str());
                current_pos += match.length();
                matched_token = true;
            }
            if (matched_token) continue;

            if (std::regex_search(current_substring, match, number_literal_regex, std::regex_constants::match_continuous)) {
                internal_operand_counts[match.str()]++;
                distinct_operands.insert(match.str());
                current_pos += match.length();
                matched_token = true;
            }
            if (matched_token) continue;

            if (std::regex_search(current_substring, match, identifier_regex, std::regex_constants::match_continuous)) {
                std::string potential_identifier = match.str();
                bool is_op_keyword = false;
                for (const std::string& op_kw : cpp_ops_and_keywords) {
                    if (op_kw == potential_identifier) {
                        is_op_keyword = true;
                        break;
                    }
                }

                if (!is_op_keyword) {
                    internal_operand_counts[potential_identifier]++;
                    distinct_operands.insert(potential_identifier);
                }
                current_pos += potential_identifier.length();
                matched_token = true;
            }
            if (matched_token) continue;

            if (current_pos < code.length() && !matched_token) {
                current_pos++;
            }
        }
    }
};

// --- Public Interface Functions ---
inline HalsteadReport getHalsteadMetricsForFile(const std::string& filepath) {
    HalsteadMetricsCalculator calculator; // Calculator will initialize its own operator list and regexes
    HalsteadReport report;
    calculator.calculate_metrics_from_file_content(filepath, report);
    return report;
}

inline void printHalsteadReport(const HalsteadReport& report, std::ostream& out = std::cout) {
    if (!report.success && !report.error_message.empty()) {
        out << "Halstead metrics calculation failed: " << report.error_message << std::endl;
        return;
    }
     if (!report.success && report.error_message.empty() && report.length == 0) {
        out << "Halstead metrics: No tokens found or file was empty/unreadable." << std::endl;
        return;
    }


    out << std::fixed << std::setprecision(2);
    out << "--- Halstead Metrics Report ---" << std::endl;
    if (report.success && report.error_message.empty()){
         out << "File Processed: Successfully" << std::endl;
    } else if (!report.error_message.empty()){
         out << "File Processed: With issues - " << report.error_message << std::endl;
    }
    out << "-----------------------------" << std::endl;
    out << "n1 (Distinct Operators): " << report.n1 << std::endl;
    out << "N1 (Total Operators):    " << report.N1 << std::endl;
    out << "n2 (Distinct Operands):  " << report.n2 << std::endl;
    out << "N2 (Total Operands):     " << report.N2 << std::endl;
    out << "-----------------------------" << std::endl;
    out << "Program Length (N):      " << report.length << std::endl;
    out << "Vocabulary Size (n):     " << report.vocabulary << std::endl;
    out << "Volume (V):              " << report.volume << std::endl;
    out << "Difficulty (D):          " << report.difficulty << std::endl;
    out << "Level (L):               " << report.level << std::endl;
    out << "Effort (E):              " << report.effort << std::endl;
    out << "Time to Program (T):     " << report.time_to_program << " seconds" << std::endl;
    out << "Estimated Bugs (B):      " << report.bugs_delivered << std::endl;
    out << "-----------------------------" << std::endl;
}

} // namespace Halstead

#endif //HALSTEAD_METRICS_H
