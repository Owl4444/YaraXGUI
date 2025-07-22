

// Learn about Dear ImGui:
// - FAQ                  https://dearimgui.com/faq
// - Getting Started      https://dearimgui.com/getting-started
// - Documentation        https://dearimgui.com/docs (same as your local docs/ folder).
// - Introduction, links and more at the top of imgui.cpp

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include <math.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <set>
#include "TextEditor.h"

#include <thread>
#include <mutex>
#include <atomic>

static std::mutex g_scan_result_mutex;
static std::atomic<bool> g_scan_in_progress{ false };


#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")



extern "C" {
#include <yara_x.h>
}

// Windows 
#include <windows.h>
#include <shobjidl.h>  // for IFileOpenDialog



// Data
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);





#include <unordered_map>

class YARAEditor {
private:
    TextEditor editor;
    bool initialized = false;
    std::string currentFile;
    bool hasUnsavedChanges = false;

    void InitializeYARASyntax() {
        if (initialized) return;

        // Set language definition for YARA
        auto lang = TextEditor::LanguageDefinition::C(); // Start with C as base

        // YARA keywords
        static const char* const keywords[] = {
            "rule", "meta", "strings", "condition", "import", "include",
            "private", "global", "and", "or", "not", "any", "all", "them",
            "for", "of", "in", "contains", "matches", "startswith", "endswith",
            "icontains", "imatches", "istartswith", "iendswith",
            "uint8", "uint16", "uint32", "uint8be", "uint16be", "uint32be",
            "int8", "int16", "int32", "int8be", "int16be", "int32be",
            "filesize", "entrypoint", "true", "false"
        };

        // YARA identifiers (built-in functions and modules)
        static const char* const identifiers[] = {
            "pe", "elf", "math", "hash", "cuckoo", "magic", "dotnet",
            "pe.entry_point", "pe.sections", "pe.imports", "pe.exports",
            "pe.version_info", "pe.machine", "pe.subsystem", "pe.timestamp",
            "elf.type", "elf.machine", "elf.entry_point", "elf.number_of_sections",
            "math.entropy", "math.mean", "math.deviation", "math.serial_correlation",
            "hash.md5", "hash.sha1", "hash.sha256", "hash.crc32", "hash.checksum32"
        };

        // Set up keywords
        for (auto& k : keywords)
            lang.mKeywords.insert(k);

        // Set up identifiers with tooltips
        for (auto& k : identifiers) {
            TextEditor::Identifier id;
            id.mDeclaration = "YARA built-in";
            lang.mIdentifiers.insert(std::make_pair(std::string(k), id));
        }

        // Comments
        lang.mCommentStart = "/*";
        lang.mCommentEnd = "*/";
        lang.mSingleLineComment = "//";



        // Case sensitivity
        lang.mCaseSensitive = true;
        lang.mAutoIndentation = true;

        // Set the language
        editor.SetLanguageDefinition(lang);
        editor.SetShowWhitespaces(false);

        // Set a default YARA rule template
        std::string defaultText = R"(rule ExampleRule {
    meta:
        description = "Example YARA rule"
        author = "Your Name"
        date = "2025-07-19"
        version = "1.0"
    
    strings:
        $string1 = "suspicious_string" nocase
        $string2 = { 4D 5A 90 00 } // MZ header
        $regex1 = /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
    
    condition:
        any of ($string*) or $regex1
}

)";
        editor.SetText(defaultText);
        initialized = true;
    }

public:
    YARAEditor() {
        InitializeYARASyntax();
    }

    void RenderYARAEditor() {
        if (!initialized) {
            InitializeYARASyntax();
        }

        // Menu bar
        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu("File")) {
                if (ImGui::MenuItem("New", "Ctrl+N")) {
                    NewFile();
                }
                if (ImGui::MenuItem("Open", "Ctrl+O")) {
                    // Implement file open dialog
                    OpenFile();
                }
                if (ImGui::MenuItem("Save", "Ctrl+S", false, hasUnsavedChanges)) {
                    SaveFile();
                }
                if (ImGui::MenuItem("Save As", "Ctrl+Shift+S")) {
                    SaveAsFile();
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Exit")) {
                    // Handle exit
                }
                ImGui::EndMenu();
            }

            if (ImGui::BeginMenu("Edit")) {
                bool ro = editor.IsReadOnly();
                if (ImGui::MenuItem("Read-only mode", nullptr, &ro))
                    editor.SetReadOnly(ro);
                ImGui::Separator();

                if (ImGui::MenuItem("Undo", "Ctrl+Z", nullptr, !ro && editor.CanUndo()))
                    editor.Undo();
                if (ImGui::MenuItem("Redo", "Ctrl+Y", nullptr, !ro && editor.CanRedo()))
                    editor.Redo();

                ImGui::Separator();

                if (ImGui::MenuItem("Copy", "Ctrl+C", nullptr, editor.HasSelection()))
                    editor.Copy();
                if (ImGui::MenuItem("Cut", "Ctrl+X", nullptr, !ro && editor.HasSelection()))
                    editor.Cut();
                if (ImGui::MenuItem("Delete", "Del", nullptr, !ro && editor.HasSelection()))
                    editor.Delete();
                if (ImGui::MenuItem("Paste", "Ctrl+V", nullptr, !ro && ImGui::GetClipboardText() != nullptr))
                    editor.Paste();

                ImGui::Separator();

                if (ImGui::MenuItem("Select all", "Ctrl+A"))
                    editor.SetSelection(TextEditor::Coordinates(), TextEditor::Coordinates(editor.GetTotalLines(), 0));
                ImGui::EndMenu();
            }

            if (ImGui::BeginMenu("View")) {
                bool ws = editor.IsShowingWhitespaces();
                if (ImGui::MenuItem("Show whitespaces", nullptr, &ws))
                    editor.SetShowWhitespaces(ws);
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }

        // Status bar
        ImGui::Text("File: %s %s | Line: %d, Column: %d | %d lines | %s",
            currentFile.empty() ? "Untitled" : currentFile.c_str(),
            hasUnsavedChanges ? "*" : "",
            editor.GetCursorPosition().mLine + 1,
            editor.GetCursorPosition().mColumn + 1,
            editor.GetTotalLines(),
            editor.IsOverwrite() ? "Ovr" : "Ins");

        // Main editor
        ImGui::Separator();
        editor.Render("YARAEditor");

        // Check for changes
        if (editor.IsTextChanged()) {
            hasUnsavedChanges = true;
        }
    }

    void NewFile() {
        std::string newContent = R"(rule NewRule {
    meta:
        description = ""
        author = ""
        date = ""
    
    strings:
        $string1 = ""
    
    condition:
        $string1
}

)";
        editor.SetText(newContent);
        currentFile.clear();
        hasUnsavedChanges = false;
    }

    void OpenFile() {
        // This would typically open a file dialog
        // For now, just a placeholder
        // You would implement platform-specific file dialog here
        // or use a library like nativefiledialog
    }

    void SaveFile() {
        if (currentFile.empty()) {
            SaveAsFile();
        }
        else {
            // Save to current file
            // Implement file saving logic
            hasUnsavedChanges = false;
        }
    }

    void SaveAsFile() {
        // This would typically open a save dialog
        // Implement platform-specific save dialog here
    }

    // Utility functions
    std::string GetText() const {
        return editor.GetText();
    }

    void SetText(const std::string& text) {
        editor.SetText(text);
        hasUnsavedChanges = false;
    }

    bool HasUnsavedChanges() const {
        return hasUnsavedChanges;
    }

    void SetReadOnly(bool readOnly) {
        editor.SetReadOnly(readOnly);
    }

    bool IsReadOnly() const {
        return editor.IsReadOnly();
    }

    // Validation function for YARA rules
    bool ValidateYARARule() const {
        std::string text = editor.GetText();

        // Basic validation checks
        bool hasRule = text.find("rule ") != std::string::npos;
        bool hasCondition = text.find("condition:") != std::string::npos;
        bool hasOpenBrace = text.find("{") != std::string::npos;
        bool hasCloseBrace = text.find("}") != std::string::npos;

        return hasRule && hasCondition && hasOpenBrace && hasCloseBrace;
    }
};

static YARAEditor yaraEditor;




class DynamicTextBuffer {
public:  // Make everything public for easier access
    std::vector<char> buffer;
    size_t current_size;
    static const size_t INITIAL_SIZE = 1024;
    static const size_t GROWTH_FACTOR = 2;

public:
    DynamicTextBuffer() : current_size(0) {
        buffer.resize(INITIAL_SIZE);
        buffer[0] = '\0';
    }

    char* data() { return buffer.data(); }
    const char* c_str() const { return buffer.data(); }
    size_t capacity() const { return buffer.size(); }
    size_t size() const { return current_size; }
    bool empty() const { return current_size == 0 || buffer[0] == '\0'; }

    void resize(size_t new_size) {
        if (new_size >= buffer.size()) {
            size_t new_capacity = max(new_size + 1, buffer.size() * GROWTH_FACTOR);
            buffer.resize(new_capacity);
        }
        current_size = new_size;
        buffer[current_size] = '\0';
    }

    void clear() {
        current_size = 0;
        buffer[0] = '\0';
    }

    std::string to_string() const {
        return std::string(buffer.data());
    }
};



/************************* MY *************************/
std::string yara_content_buffer = "";
std::string compilation_output_buffer = "";
static char g_SelectedYaraFile[512] = "";
static char g_SelectedDir[MAX_PATH] = "";
DynamicTextBuffer g_YaraBuffer;
static int selected_result = -1;

// YARA related globals
int g_files_scanned = 0;
int g_files_matched = 0;
YRX_RULES* g_compiled_rules = nullptr;
YRX_SCANNER* g_scanner = nullptr;
std::set<std::string> unique_files;
std::string selected_file = "";



struct PatternMatch {
    std::string pattern_id;  // like $string1, $hex1 etc
    size_t offset;  // of match
    size_t length;  // length of the match
    std::vector<uint8_t> data;  //actual matched bytes
    std::string data_preview; // human readable data
    std::string hex_dump;   // HEX representation in table
};


// Structure to store scan results
struct ScanResult {
    std::string filename;
    std::string rule_name;
    std::string rule_namespace;

    std::vector<PatternMatch> pattern_matches;

    size_t GetTotalMatches() const { return pattern_matches.size(); }
    size_t GetUniquePatterns() const {
        std::set<std::string> unique_patterns;
        for (const auto& match : pattern_matches) {
            unique_patterns.insert(match.pattern_id);
        }
        return unique_patterns.size();
    }
};

static std::vector<ScanResult> g_scan_results;


struct PatternCallbackData {
    ScanResult* result;
    std::string current_pattern_id;
    std::string current_file_path;
};

// prototypes
static std::vector<char> read_file(const std::string& file_path);
bool scan_file(YRX_SCANNER* scanner, const std::string& file_path);
void enhanced_match_callback(const YRX_MATCH* match, void* user_data);


void enhanced_match_callback(const YRX_MATCH* match, void* user_data) {
    auto* callback_data = static_cast<PatternCallbackData*>(user_data);
    PatternMatch pattern_match;
    pattern_match.pattern_id = callback_data->current_pattern_id;
    pattern_match.offset = match->offset;
    pattern_match.length = match->length;


    // read the actual data from the file
    try {
        std::ifstream file(callback_data->current_file_path, std::ios::binary);
        if (file.is_open()) {
            file.seekg(match->offset); // go to that location in the file before starting to read
            if (!file.fail()) {
                pattern_match.data.resize(match->length);
                file.read(reinterpret_cast<char*>(pattern_match.data.data()), match->length);

                size_t preview_limit = min(pattern_match.data.size(), size_t(255));
                pattern_match.data_preview = "";
                pattern_match.hex_dump = "";

                for (size_t i = 0; i < preview_limit; i++) {
                    uint8_t byte = pattern_match.data[i];

                    if (std::isprint(byte)) {
                        pattern_match.data_preview += static_cast<char>(byte);
                    }
                    else {
                        pattern_match.data_preview += '.';
                    }

                    char hex[4];
                    sprintf(hex, "%02X ", byte);
                    pattern_match.hex_dump += hex;
                }

                if (pattern_match.data.size() > preview_limit) {
                    pattern_match.data_preview += "...";
                    pattern_match.hex_dump += "...";
                }
            }
            file.close();
        }
    }
    catch (const std::exception& e) {
        pattern_match.data_preview = "[Read Error]";
        pattern_match.hex_dump = "[Read Error]";
    }

    // add to result
    callback_data->result->pattern_matches.push_back(pattern_match);

}

// get pattern identifiers
void enhanced_pattern_callback(const YRX_PATTERN* pattern, void* user_data) {
    auto* callback_data = static_cast<PatternCallbackData*>(user_data);

    // Get pattern identifier using yrx_pattern_identifier
    const uint8_t* ident;
    size_t len;
    if (yrx_pattern_identifier(pattern, &ident, &len) == YRX_SUCCESS) {
        callback_data->current_pattern_id = std::string(reinterpret_cast<const char*>(ident), len);

        // Iterate over matches for this pattern using yrx_pattern_iter_matches
        yrx_pattern_iter_matches(pattern, enhanced_match_callback, callback_data);
    }
}


void on_matching_rule_callback(const struct YRX_RULE* rule, void* user_data) {
    std::string* current_file = reinterpret_cast<std::string*>(user_data);

    // Create new scan result entry
    ScanResult result;
    result.filename = *current_file;

    // Get rule identifier
    const uint8_t* rule_identifier = nullptr;
    size_t rule_id_length = 0;
    if (yrx_rule_identifier(rule, &rule_identifier, &rule_id_length) == YRX_SUCCESS) {
        result.rule_name = std::string(reinterpret_cast<const char*>(rule_identifier), rule_id_length);

        // Get rule namespace
        const uint8_t* rule_ns = nullptr;
        size_t rule_ns_length = 0;
        if (yrx_rule_namespace(rule, &rule_ns, &rule_ns_length) == YRX_SUCCESS) {
            result.rule_namespace = std::string(reinterpret_cast<const char*>(rule_ns), rule_ns_length);
        }

        // Setup callback data for pattern iteration
        PatternCallbackData callback_data;
        callback_data.result = &result;
        callback_data.current_file_path = *current_file;

        // Get all pattern matches for this rule using yrx_rule_iter_patterns
        yrx_rule_iter_patterns(rule, enhanced_pattern_callback, &callback_data);

        // THREAD SAFE: Add to global results with mutex protection
        {
            std::lock_guard<std::mutex> lock(g_scan_result_mutex);
            g_scan_results.push_back(result);
        }

        // Enhanced output message
        compilation_output_buffer += "\n[MATCH] " + result.rule_name +
            " in " + std::filesystem::path(result.filename).filename().string() +
            " (" + std::to_string(result.GetUniquePatterns()) + " patterns, " +
            std::to_string(result.GetTotalMatches()) + " matches)\n";

        g_files_matched++;
    }
}

bool scan_file(YRX_SCANNER* scanner, const std::string& file_path) {
    // Read file data
    std::vector<char> file_data = read_file(file_path);
    if (file_data.empty()) {
        compilation_output_buffer += "[ERR] Failed to read file: " + file_path + "\n";
        return false;
    }

    // FIXED: Pass filename to callback via user_data
    std::string* file_path_ptr = new std::string(file_path);

    // FIXED: Set callback before scanning (not during scan)
    YRX_RESULT result = yrx_scanner_on_matching_rule(
        scanner,
        on_matching_rule_callback,
        file_path_ptr
    );

    if (result != YRX_SUCCESS) {
        compilation_output_buffer += "[ERR] Failed to set callback for: " + file_path + "\n";
        delete file_path_ptr;
        return false;
    }

    result = yrx_scanner_scan(
        scanner,
        reinterpret_cast<const uint8_t*>(file_data.data()),
        file_data.size()
    );

    delete file_path_ptr;  // Clean up

    if (result != YRX_SUCCESS) {
        if (result == YRX_SCAN_TIMEOUT) {
            compilation_output_buffer += "[ERR] Scan timeout for: " + file_path + "\n";
        }
        else if (result == YRX_SYNTAX_ERROR) {
            compilation_output_buffer += "[ERR] Syntax error for: " + file_path + "\n";
        }
        else {
            compilation_output_buffer += "[ERR] Failed to scan: " + file_path + "\n";
        }
        return false;
    }

    g_files_scanned++;
    return true;
}

// return vector of bytes of file content
static std::vector<char> read_file(const std::string& file_path) {

    compilation_output_buffer += "\n[INFO] Reading ";
    compilation_output_buffer += file_path;

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return {};
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    std::vector<char> buffer(file_size);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), file_size);
    file.close();

    return buffer;

}

bool compile_yara_rules() {
    compilation_output_buffer += "[INFO] Starting YARA-X compilation...\n";

    // Clean up existing resources
    if (g_scanner) {
        yrx_scanner_destroy(g_scanner);
        g_scanner = nullptr;
    }
    if (g_compiled_rules) {
        yrx_rules_destroy(g_compiled_rules);
        g_compiled_rules = nullptr;
    }

    // Get rule content
    std::string rule_content;
    if (!g_YaraBuffer.empty()) {
        rule_content = g_YaraBuffer.to_string();
    }
    else if (strlen(g_SelectedYaraFile) > 0) {
        // Use read_file function for consistency
        //compilation_output_buffer += "[INFO] Reading YARA file: " + std::string(g_SelectedYaraFile) + "\n";
        std::vector<char> file_data = read_file(g_SelectedYaraFile);
        if (!file_data.empty()) {
            rule_content = std::string(file_data.data(), file_data.size());
        }
        else {
            compilation_output_buffer += "[ERR] Cannot read YARA file: " + std::string(g_SelectedYaraFile) + "\n";
            return false;
        }
    }
    else {
        compilation_output_buffer += "[ERR] No YARA rule content available\n";
        return false;
    }

    // Compile rules
    YRX_RESULT result = yrx_compile(rule_content.c_str(), &g_compiled_rules);
    if (result != YRX_SUCCESS) {
        const char* error_msg = yrx_last_error();
        compilation_output_buffer += "[ERR] Compilation failed: ";
        compilation_output_buffer += error_msg ? error_msg : "Unknown error";
        compilation_output_buffer += "\n";
        return false;
    }

    // Create scanner
    result = yrx_scanner_create(g_compiled_rules, &g_scanner);
    if (result != YRX_SUCCESS) {
        const char* error_msg = yrx_last_error();
        compilation_output_buffer += "[ERR] Scanner creation failed: ";
        compilation_output_buffer += error_msg ? error_msg : "Unknown error";
        compilation_output_buffer += "\n";
        yrx_rules_destroy(g_compiled_rules);
        g_compiled_rules = nullptr;
        return false;
    }

    compilation_output_buffer += "[SUCCESS] YARA rules compiled successfully!\n";
    return true;
}


// Thread-safe scan directory function
void scan_directory_async() {
    // Prevent multiple scans
    if (g_scan_in_progress.exchange(true)) {
        compilation_output_buffer += "[INFO] Scan already in progress\n";
        return;
    }

    std::thread([=]() {
        if (!g_scanner) {
            compilation_output_buffer += "[ERR] No compiled rules available\n";
            g_scan_in_progress = false;
            return;
        }

        if (strlen(g_SelectedDir) == 0) {
            compilation_output_buffer += "[ERR] No directory selected\n";
            g_scan_in_progress = false;
            return;
        }

        compilation_output_buffer += "[INFO] Starting directory scan...\n";

        // THREAD SAFE: Clear previous results
        {
            std::lock_guard<std::mutex> lock(g_scan_result_mutex);
            g_scan_results.clear();
        }

        g_files_scanned = 0;
        g_files_matched = 0;

        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(g_SelectedDir)) {
                if (entry.is_regular_file()) {
                    scan_file(g_scanner, entry.path().string());

                    // Progress update every 10 files
                    if (g_files_scanned % 10 == 0) {
                        compilation_output_buffer += "[PROGRESS] Scanned " +
                            std::to_string(g_files_scanned) + " files...\n";
                    }
                }
            }

            compilation_output_buffer += "[COMPLETE] Scan finished!\n";
            compilation_output_buffer += "Files scanned: " + std::to_string(g_files_scanned) + "\n";
            compilation_output_buffer += "Files matched: " + std::to_string(g_files_matched) + "\n";

            // THREAD SAFE: Get result count
            size_t total_results;
            {
                std::lock_guard<std::mutex> lock(g_scan_result_mutex);
                total_results = g_scan_results.size();
            }
            compilation_output_buffer += "Total matches: " + std::to_string(total_results) + "\n";

        }
        catch (const std::exception& e) {
            compilation_output_buffer += "[ERR] Directory scan failed: " + std::string(e.what()) + "\n";
        }

        g_scan_in_progress = false;
        }).detach();
}


// Generic one
std::string ShowSaveDialog(const char* filter, const char* defaultExt, const char* title) {
    char szFile[260] = "";

    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = filter;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = defaultExt;

    if (GetSaveFileNameA(&ofn)) {
        return std::string(szFile);
    }

    return "";  // User cancelled or error
}


void ShowDirectorySelector_COM()
{
    if (ImGui::Button("Select Folder…"))
    {
        // Initialize COM (once in your app)
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

        IFileOpenDialog* pDlg = nullptr;
        if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr,
            CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&pDlg))))
        {
            // configure for folder picking
            DWORD opts;
            pDlg->GetOptions(&opts);
            pDlg->SetOptions(opts | FOS_PICKFOLDERS);

            if (SUCCEEDED(pDlg->Show(NULL)))
            {
                IShellItem* pItem = nullptr;
                if (SUCCEEDED(pDlg->GetResult(&pItem)))
                {
                    PWSTR wpath = nullptr;
                    if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &wpath)))
                    {

                        WideCharToMultiByte(CP_UTF8, 0, wpath, -1,
                            g_SelectedDir, MAX_PATH,
                            nullptr, nullptr);
                        CoTaskMemFree(wpath);
                    }
                    pItem->Release();
                }
            }
            pDlg->Release();
        }

        CoUninitialize();
    }

}

void ShowFileSelector() {
    if (ImGui::Button("Browse YARA File")) {
        OPENFILENAMEA ofn = {};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = nullptr;
        ofn.lpstrFile = g_SelectedYaraFile;
        ofn.nMaxFile = sizeof(g_SelectedYaraFile);
        ofn.lpstrFilter = "YARA Files\0*.yara;*.yar\0All Files\0*.*\0";
        ofn.lpstrTitle = "Select a YARA file";
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

        if (GetOpenFileNameA(&ofn)) {
            // Use the read_file function to load content
            std::vector<char> file_data = read_file(g_SelectedYaraFile);

            if (!file_data.empty()) {
                g_YaraBuffer.clear();
                g_YaraBuffer.resize(file_data.size());

                std::memcpy(g_YaraBuffer.data(), file_data.data(), file_data.size());

                compilation_output_buffer += "\n[INFO] Loaded YARA file: " + std::string(g_SelectedYaraFile) + "\n";
                compilation_output_buffer += "[INFO] File size: " + std::to_string(file_data.size()) + " bytes\n";
            }
            else {
                compilation_output_buffer += "[ERR] Failed to read YARA file: " + std::string(g_SelectedYaraFile) + "\n";
            }
        }
    }
}

struct DynamicTextCallbackData {
    DynamicTextBuffer* buffer;
};

static int DynamicTextCallback(ImGuiInputTextCallbackData* data) {
    DynamicTextCallbackData* user_data = static_cast<DynamicTextCallbackData*>(data->UserData);
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        DynamicTextBuffer* buffer = user_data->buffer;
        buffer->resize(data->BufTextLen);
        data->Buf = buffer->data();
    }

    return 0;
}

size_t GetTotalMatchCount() {
    std::lock_guard<std::mutex> lock(g_scan_result_mutex);
    size_t total = 0;
    for (const auto& result : g_scan_results) {
        total += result.GetTotalMatches();
    }
    return total;
}

size_t GetUniqueFileCount() {
    std::lock_guard<std::mutex> lock(g_scan_result_mutex);
    std::set<std::string> unique_files;
    for (const auto& result : g_scan_results) {
        unique_files.insert(result.filename);
    }
    return unique_files.size();
}


void RenderFileInfoSection(float col_width, float col_height) {
    ImGui::BeginGroup();
    ImGui::Text("Files with Matches (%zu)", GetUniqueFileCount());
    ImGui::Separator();
    ImGui::BeginChild("AllFilesList", ImVec2(col_width, -1), true, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_AlwaysHorizontalScrollbar);

    // FIXED: Properly declare unique_files
    std::set<std::string> unique_files;
    {
        std::lock_guard<std::mutex> lock(g_scan_result_mutex);
        for (const auto& result : g_scan_results) {
            unique_files.insert(result.filename);
        }
    }


    for (const auto& file : unique_files) {
        std::string filename = std::filesystem::path(file).filename().string();

        // FIXED: Use the correct method to count matches
        int total_matches = 0;
        std::set<std::string> rules_for_file;
        std::set<std::string> patterns_for_file;

        {
            std::lock_guard<std::mutex> lock(g_scan_result_mutex);
            for (const auto& result : g_scan_results) {
                if (result.filename == file) {
                    total_matches += result.GetTotalMatches();  // FIXED: Use GetTotalMatches()
                    rules_for_file.insert(result.rule_name);

                    // Count unique patterns
                    for (const auto& match : result.pattern_matches) {
                        patterns_for_file.insert(match.pattern_id);
                    }
                }
            }
        }


        std::string display_text = " (" + std::to_string(rules_for_file.size()) + " rules, " +
            std::to_string(patterns_for_file.size()) + " patterns) " + filename;

        if (ImGui::Selectable(display_text.c_str(), selected_file == file)) {
            selected_file = file;
        }

        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Full path: %s\nRules matched: %zu\nUnique patterns: %zu\nTotal matches: %d",
                file.c_str(), rules_for_file.size(), patterns_for_file.size(), total_matches);
        }
    }

    if (unique_files.empty()) {
        ImGui::TextDisabled("No files scanned yet");
        ImGui::TextDisabled("Run a scan to see results");
    }

    ImGui::EndChild();
    ImGui::EndGroup();
}

// to view all results 
void RenderPatternTableSectionWithClearButton(float right_bottom_width, float right_bottom_height) {
    // Use all remaining space in the parent
    ImGui::BeginChild("TableSection", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);

    // Show "Clear Selection" button only when a file is selected
    bool show_clear_button = !selected_file.empty();
    if (show_clear_button) {
        if (ImGui::Button("Show All Files")) {
            selected_file.clear();
            selected_result = -1; // Also clear selected row
        }
        ImGui::SameLine();

        // Show current selection info
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 1.0f, 1.0f), "Filtered by: %s",
            std::filesystem::path(selected_file).filename().string().c_str());
    }

    // THREAD SAFE: Create local copy of results for rendering
    std::vector<ScanResult> local_results;
    {
        std::lock_guard<std::mutex> lock(g_scan_result_mutex);
        local_results = g_scan_results;
    }

    // Filter results for selected file
    std::vector<ScanResult> filtered_results;
    size_t total_matches_for_file = 0;

    if (!selected_file.empty()) {
        for (const auto& result : local_results) {
            if (result.filename == selected_file) {
                filtered_results.push_back(result);
                total_matches_for_file += result.GetTotalMatches();
            }
        }

        ImGui::Text("PATTERN MATCHES FOR: %s (%zu patterns)",
            std::filesystem::path(selected_file).filename().string().c_str(),
            total_matches_for_file);
    }
    else {
        filtered_results = local_results;
        ImGui::Text("PATTERN MATCHES - ALL FILES (%zu total)", GetTotalMatchCount());
    }

    ImGui::Separator();

    // Table uses remaining space automatically with ScrollY
    if (ImGui::BeginTable("ScanResults", 6,
        ImGuiTableFlags_Borders |
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_ScrollX |
        ImGuiTableFlags_Resizable)) {

        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Rule", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Pattern ID", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Data Preview", ImGuiTableColumnFlags_WidthFixed, 200.0f);
        ImGui::TableSetupColumn("Hex Dump", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        // Render all rows
        int row_id = 0;
        for (const auto& result : filtered_results) {
            for (const auto& pattern_match : result.pattern_matches) {
                ImGui::PushID(row_id);
                ImGui::TableNextRow();

                if (selected_result == row_id) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(100, 100, 150, 100));
                }

                ImGui::TableSetColumnIndex(0);
                std::string filename = std::filesystem::path(result.filename).filename().string();
                if (ImGui::Selectable(filename.c_str(), selected_result == row_id,
                    ImGuiSelectableFlags_SpanAllColumns)) {
                    selected_result = row_id;
                }

                // Tooltip
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Full path: %s\nRule: %s\nPattern: %s\nOffset: 0x%X",
                        result.filename.c_str(),
                        result.rule_name.c_str(),
                        pattern_match.pattern_id.c_str(),
                        (unsigned int)pattern_match.offset);
                }

                // Context menu
                char popup_id[64];
                sprintf(popup_id, "ContextMenu_%d", row_id);

                if (ImGui::BeginPopupContextItem(popup_id)) {
                    if (ImGui::MenuItem("Copy Pattern ID")) {
                        ImGui::SetClipboardText(pattern_match.pattern_id.c_str());
                    }
                    if (ImGui::MenuItem("Copy Offset")) {
                        char offset_str[32];
                        sprintf(offset_str, "0x%X", (unsigned int)pattern_match.offset);
                        ImGui::SetClipboardText(offset_str);
                    }
                    if (ImGui::MenuItem("Copy Data Preview")) {
                        ImGui::SetClipboardText(pattern_match.data_preview.c_str());
                    }
                    if (ImGui::MenuItem("Copy Hex Dump")) {
                        ImGui::SetClipboardText(pattern_match.hex_dump.c_str());
                    }
                    if (ImGui::MenuItem("Copy Full File Path")) {
                        ImGui::SetClipboardText(result.filename.c_str());
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("Copy All Info")) {
                        char full_info[1024];
                        sprintf(full_info, "File: %s\nRule: %s\nPattern: %s\nOffset: 0x%X\nData: %s\nHex: %s",
                            result.filename.c_str(),
                            result.rule_name.c_str(),
                            pattern_match.pattern_id.c_str(),
                            (unsigned int)pattern_match.offset,
                            pattern_match.data_preview.c_str(),
                            pattern_match.hex_dump.c_str());
                        ImGui::SetClipboardText(full_info);
                    }
                    ImGui::EndPopup();
                }

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", result.rule_name.c_str());

                ImGui::TableSetColumnIndex(2);
                // Color-code different pattern types
                if (pattern_match.pattern_id.find("$string") != std::string::npos) {
                    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "%s", pattern_match.pattern_id.c_str());
                }
                else if (pattern_match.pattern_id.find("$hex") != std::string::npos) {
                    ImGui::TextColored(ImVec4(0.8f, 0.4f, 0.2f, 1.0f), "%s", pattern_match.pattern_id.c_str());
                }
                else if (pattern_match.pattern_id.find("$regex") != std::string::npos) {
                    ImGui::TextColored(ImVec4(0.2f, 0.4f, 0.8f, 1.0f), "%s", pattern_match.pattern_id.c_str());
                }
                else {
                    ImGui::Text("%s", pattern_match.pattern_id.c_str());
                }

                ImGui::TableSetColumnIndex(3);
                ImGui::Text("0x%X", (unsigned int)pattern_match.offset);

                ImGui::TableSetColumnIndex(4);
                if (!pattern_match.data_preview.empty()) {
                    ImGui::Text("%s", pattern_match.data_preview.c_str());

                    if (ImGui::IsItemHovered()) {
                        ImGui::BeginTooltip();
                        ImGui::Text("Pattern: %s", pattern_match.pattern_id.c_str());
                        ImGui::Text("Length: %zu bytes", pattern_match.length);
                        ImGui::Text("Preview: %s", pattern_match.data_preview.c_str());
                        ImGui::EndTooltip();
                    }
                }
                else {
                    ImGui::TextDisabled("[No data]");
                }

                ImGui::TableSetColumnIndex(5);
                if (!pattern_match.hex_dump.empty()) {
                    ImGui::Text("%s", pattern_match.hex_dump.c_str());

                    if (ImGui::IsItemHovered()) {
                        ImGui::BeginTooltip();
                        ImGui::Text("Full hex dump:");

                        // Show full hex dump (up to 256 bytes)
                        std::string full_hex;
                        for (size_t i = 0; i < pattern_match.data.size() && i < 256; i++) {
                            if (i > 0 && i % 16 == 0) full_hex += "\n";
                            char hex[4];
                            sprintf(hex, "%02X ", pattern_match.data[i]);
                            full_hex += hex;
                        }
                        if (pattern_match.data.size() > 256) full_hex += "\n...";

                        ImGui::Text("%s", full_hex.c_str());
                        ImGui::EndTooltip();
                    }
                }
                else {
                    ImGui::TextDisabled("[No hex]");
                }

                ImGui::PopID();
                row_id++;
            }
        }

        // Show message if no patterns found
        if (filtered_results.empty()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (!selected_file.empty()) {
                ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "No patterns found for selected file");
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("Try selecting a different file or use 'Show All Files'");
            }
            else {
                ImGui::TextDisabled("No scan results available - run a scan first");
            }
        }

        ImGui::EndTable();
    }

    ImGui::EndChild();

}


void RenderMatchDetailsSection(float col_width, float col_height) {
    ImGui::BeginGroup();
    ImGui::Text("Rule Metadata");
    ImGui::Separator();
    ImGui::BeginChild("MetadataTable", ImVec2(col_width, -1), true, ImGuiWindowFlags_AlwaysVerticalScrollbar);

    if (!selected_file.empty()) {
        // THREAD SAFE: Create local copy of relevant results
        std::vector<ScanResult> relevant_results;
        {
            std::lock_guard<std::mutex> lock(g_scan_result_mutex);
            for (const auto& result : g_scan_results) {
                if (result.filename == selected_file) {
                    relevant_results.push_back(result);
                }
            }
        }

        std::set<std::string> rules_for_selected_file;
        for (const auto& result : relevant_results) {
            rules_for_selected_file.insert(result.rule_name);
        }

        if (ImGui::BeginTable("MetadataTable", 2,
            ImGuiTableFlags_Borders |
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_ScrollX |
            ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            // File information
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("File");
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s", std::filesystem::path(selected_file).filename().string().c_str());

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("Full Path");
            ImGui::TableSetColumnIndex(1);
            ImGui::TextWrapped("%s", selected_file.c_str());

            // File size
            try {
                if (std::filesystem::exists(selected_file)) {
                    auto file_size = std::filesystem::file_size(selected_file);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("Size");
                    ImGui::TableSetColumnIndex(1);
                    if (file_size > 1024 * 1024) {
                        ImGui::Text("%.2f MB (%zu bytes)", file_size / (1024.0 * 1024.0), file_size);
                    }
                    else if (file_size > 1024) {
                        ImGui::Text("%.2f KB (%zu bytes)", file_size / 1024.0, file_size);
                    }
                    else {
                        ImGui::Text("%zu bytes", file_size);
                    }
                }
            }
            catch (...) {}

            // Enhanced rule information
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("Rules Hit");
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%zu", rules_for_selected_file.size());

            // Total matches
            int total_matches = 0;
            std::set<std::string> all_patterns;
            for (const auto& result : relevant_results) {
                total_matches += result.GetTotalMatches();
                for (const auto& match : result.pattern_matches) {
                    all_patterns.insert(match.pattern_id);
                }
            }

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("Total Pattern Matches");
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%d", total_matches);

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("Unique Patterns");
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%zu", all_patterns.size());

            // List each rule with details
            for (const auto& rule_name : rules_for_selected_file) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("Rule");
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", rule_name.c_str());

                // Find namespace and match count for this rule
                for (const auto& result : relevant_results) {
                    if (result.rule_name == rule_name) {
                        if (!result.rule_namespace.empty()) {
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("Namespace");
                            ImGui::TableSetColumnIndex(1);
                            ImGui::Text("%s", result.rule_namespace.c_str());
                        }

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("Rule Matches");
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%zu", result.GetTotalMatches());

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("Rule Patterns");
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%zu", result.GetUniquePatterns());
                        break;
                    }
                }
            }

            ImGui::EndTable();
        }
    }
    else {
        ImGui::TextDisabled("Select a file to view metadata");
        ImGui::Separator();
        ImGui::TextDisabled("Metadata will include:");
        ImGui::TextDisabled("• File information");
        ImGui::TextDisabled("• File size");
        ImGui::TextDisabled("• Matched rules");
        ImGui::TextDisabled("• Rule namespaces");
    }

    ImGui::EndChild();
    ImGui::EndGroup();
}

// Export functions for IR analysis
void ExportToCSV(const std::vector<ScanResult>& results, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        compilation_output_buffer += "[ERROR] Failed to create CSV file: " + filename + "\n";
        return;
    }

    // CSV Header
    file << "Timestamp,File_Path,File_Name,File_Size_Bytes,Rule_Name,Rule_Namespace,";
    file << "Pattern_ID,Pattern_Type,Offset_Hex,Offset_Decimal,Match_Length,";
    file << "Data_Preview,Hex_Dump,MD5_Hash,SHA256_Hash\n";

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&time_t));

    for (const auto& result : results) {
        // Get file information
        std::string file_size = "Unknown";
        std::string md5_hash = "Not_Calculated";
        std::string sha256_hash = "Not_Calculated";

        try {
            if (std::filesystem::exists(result.filename)) {
                auto size = std::filesystem::file_size(result.filename);
                file_size = std::to_string(size);
            }
        }
        catch (...) {}

        std::string filename_only = std::filesystem::path(result.filename).filename().string();

        for (const auto& pattern : result.pattern_matches) {
            // Escape CSV fields
            auto escape_csv = [](const std::string& field) {
                std::string escaped = field;
                // Replace quotes with double quotes and wrap in quotes if contains comma/quote/newline
                if (escaped.find(',') != std::string::npos ||
                    escaped.find('"') != std::string::npos ||
                    escaped.find('\n') != std::string::npos) {
                    size_t pos = 0;
                    while ((pos = escaped.find('"', pos)) != std::string::npos) {
                        escaped.replace(pos, 1, "\"\"");
                        pos += 2;
                    }
                    escaped = "\"" + escaped + "\"";
                }
                return escaped;
                };

            // Determine pattern type
            std::string pattern_type = "Unknown";
            if (pattern.pattern_id.find("$string") != std::string::npos) pattern_type = "String";
            else if (pattern.pattern_id.find("$hex") != std::string::npos) pattern_type = "Hex";
            else if (pattern.pattern_id.find("$regex") != std::string::npos) pattern_type = "Regex";

            file << timestamp << ","
                << escape_csv(result.filename) << ","
                << escape_csv(filename_only) << ","
                << file_size << ","
                << escape_csv(result.rule_name) << ","
                << escape_csv(result.rule_namespace) << ","
                << escape_csv(pattern.pattern_id) << ","
                << pattern_type << ","
                << "0x" << std::hex << pattern.offset << std::dec << ","
                << pattern.offset << ","
                << pattern.length << ","
                << escape_csv(pattern.data_preview) << ","
                << escape_csv(pattern.hex_dump) << ","
                << md5_hash << ","
                << sha256_hash << "\n";
        }
    }

    file.close();
    compilation_output_buffer += "[SUCCESS] Exported " + std::to_string(results.size()) +
        " results to CSV: " + filename + "\n";
}

void ExportToJSON(const std::vector<ScanResult>& results, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        compilation_output_buffer += "[ERROR] Failed to create JSON file: " + filename + "\n";
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S UTC", gmtime(&time_t));

    file << "{\n";
    file << "  \"scan_metadata\": {\n";
    file << "    \"timestamp\": \"" << timestamp << "\",\n";
    file << "    \"tool\": \"YaraXGUI\",\n";
    file << "    \"total_files_scanned\": " << g_files_scanned << ",\n";
    file << "    \"total_files_matched\": " << g_files_matched << ",\n";
    file << "    \"total_pattern_matches\": " << GetTotalMatchCount() << ",\n";
    file << "    \"yara_rules_file\": \"" << (strlen(g_SelectedYaraFile) > 0 ? g_SelectedYaraFile : "Inline Rules") << "\",\n";
    file << "    \"scan_directory\": \"" << (strlen(g_SelectedDir) > 0 ? g_SelectedDir : "Unknown") << "\"\n";
    file << "  },\n";
    file << "  \"results\": [\n";

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& result = results[i];

        file << "    {\n";
        file << "      \"file_path\": \"" << result.filename << "\",\n";
        file << "      \"file_name\": \"" << std::filesystem::path(result.filename).filename().string() << "\",\n";

        // File metadata
        try {
            if (std::filesystem::exists(result.filename)) {
                auto size = std::filesystem::file_size(result.filename);
                file << "      \"file_size_bytes\": " << size << ",\n";
            }
            else {
                file << "      \"file_size_bytes\": null,\n";
            }
        }
        catch (...) {
            file << "      \"file_size_bytes\": null,\n";
        }

        file << "      \"rule_name\": \"" << result.rule_name << "\",\n";
        file << "      \"rule_namespace\": \"" << result.rule_namespace << "\",\n";
        file << "      \"pattern_matches\": [\n";

        for (size_t j = 0; j < result.pattern_matches.size(); ++j) {
            const auto& pattern = result.pattern_matches[j];

            std::string pattern_type = "unknown";
            if (pattern.pattern_id.find("$string") != std::string::npos) pattern_type = "string";
            else if (pattern.pattern_id.find("$hex") != std::string::npos) pattern_type = "hex";
            else if (pattern.pattern_id.find("$regex") != std::string::npos) pattern_type = "regex";

            file << "        {\n";
            file << "          \"pattern_id\": \"" << pattern.pattern_id << "\",\n";
            file << "          \"pattern_type\": \"" << pattern_type << "\",\n";
            file << "          \"offset_decimal\": " << pattern.offset << ",\n";
            file << "          \"offset_hex\": \"0x" << std::hex << pattern.offset << std::dec << "\",\n";
            file << "          \"length\": " << pattern.length << ",\n";
            file << "          \"data_preview\": \"" << pattern.data_preview << "\",\n";
            file << "          \"hex_dump\": \"" << pattern.hex_dump << "\"\n";
            file << "        }" << (j < result.pattern_matches.size() - 1 ? "," : "") << "\n";
        }

        file << "      ]\n";
        file << "    }" << (i < results.size() - 1 ? "," : "") << "\n";
    }

    file << "  ]\n";
    file << "}\n";

    file.close();
    compilation_output_buffer += "[SUCCESS] Exported " + std::to_string(results.size()) +
        " results to JSON: " + filename + "\n";
}

void ExportToIRReport(const std::vector<ScanResult>& results, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        compilation_output_buffer += "[ERROR] Failed to create IR report: " + filename + "\n";
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S UTC", gmtime(&time_t));

    // IR Report Header
    file << "=" << std::string(80, '=') << "\n";
    file << "YARA SCAN INCIDENT RESPONSE REPORT\n";
    file << "=" << std::string(80, '=') << "\n\n";

    file << "SCAN METADATA:\n";
    file << "-" << std::string(40, '-') << "\n";
    file << "Scan Date/Time:      " << timestamp << "\n";
    file << "Tool:                YaraXGUI\n";
    file << "YARA Rules File:     " << (strlen(g_SelectedYaraFile) > 0 ? g_SelectedYaraFile : "Inline Rules") << "\n";
    file << "Scan Directory:      " << (strlen(g_SelectedDir) > 0 ? g_SelectedDir : "Unknown") << "\n";
    file << "Total Files Scanned: " << g_files_scanned << "\n";
    file << "Files with Matches:  " << g_files_matched << "\n";
    file << "Total Pattern Hits:  " << GetTotalMatchCount() << "\n\n";

    // Executive Summary
    file << "EXECUTIVE SUMMARY:\n";
    file << "-" << std::string(40, '-') << "\n";
    std::set<std::string> unique_files, unique_rules;
    for (const auto& result : results) {
        unique_files.insert(result.filename);
        unique_rules.insert(result.rule_name);
    }

    file << "• " << unique_files.size() << " unique files triggered YARA rules\n";
    file << "• " << unique_rules.size() << " different YARA rules were triggered\n";
    file << "• " << GetTotalMatchCount() << " total pattern matches detected\n\n";

    // Detailed Findings
    file << "DETAILED FINDINGS:\n";
    file << "=" << std::string(80, '=') << "\n\n";

    int finding_number = 1;
    std::map<std::string, std::vector<ScanResult>> files_grouped;
    for (const auto& result : results) {
        files_grouped[result.filename].push_back(result);
    }

    for (const auto& [filepath, file_results] : files_grouped) {
        file << "FINDING #" << finding_number++ << "\n";
        file << "-" << std::string(60, '-') << "\n";
        file << "File: " << std::filesystem::path(filepath).filename().string() << "\n";
        file << "Full Path: " << filepath << "\n";

        try {
            if (std::filesystem::exists(filepath)) {
                auto size = std::filesystem::file_size(filepath);
                file << "File Size: " << size << " bytes";
                if (size > 1024 * 1024) file << " (" << (size / (1024 * 1024)) << " MB)";
                else if (size > 1024) file << " (" << (size / 1024) << " KB)";
                file << "\n";
            }
        }
        catch (...) {}

        std::set<std::string> rules_hit;
        size_t total_patterns = 0;
        for (const auto& result : file_results) {
            rules_hit.insert(result.rule_name);
            total_patterns += result.pattern_matches.size();
        }

        file << "Rules Triggered: " << rules_hit.size() << " (" << total_patterns << " pattern matches)\n\n";

        for (const auto& result : file_results) {
            file << "  RULE: " << result.rule_name << "\n";
            if (!result.rule_namespace.empty()) {
                file << "  Namespace: " << result.rule_namespace << "\n";
            }
            file << "  Pattern Matches:\n";

            for (const auto& pattern : result.pattern_matches) {
                file << "    • " << pattern.pattern_id << " at offset 0x"
                    << std::hex << pattern.offset << std::dec
                    << " (length: " << pattern.length << " bytes)\n";
                file << "      Data: " << pattern.data_preview << "\n";
                if (!pattern.hex_dump.empty()) {
                    file << "      Hex:  " << pattern.hex_dump.substr(0, 60);
                    if (pattern.hex_dump.length() > 60) file << "...";
                    file << "\n";
                }
            }
            file << "\n";
        }
        file << "\n";
    }

    // Recommendations
    file << "RECOMMENDATIONS:\n";
    file << "=" << std::string(80, '=') << "\n";
    file << "1. Quarantine or isolate all flagged files immediately\n";
    file << "2. Perform deeper malware analysis on suspicious files\n";
    file << "3. Check network logs for communications from affected systems\n";
    file << "4. Scan other systems for similar indicators\n";
    file << "5. Review file origins and distribution vectors\n";
    file << "6. Update detection rules based on findings\n\n";

    file << "END OF REPORT\n";
    file << "=" << std::string(80, '=') << "\n";

    file.close();
    compilation_output_buffer += "[SUCCESS] Generated IR report: " + filename + "\n";
}



// Modified RenderPatternTableSection with export functionality
void RenderPatternTableSection(float right_bottom_width, float right_bottom_height) {
    ImGui::BeginChild("TableSection", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);

    // Show "Clear Selection" button only when a file is selected
    bool show_clear_button = !selected_file.empty();
    if (show_clear_button) {
        if (ImGui::Button("Show All Files")) {
            selected_file.clear();
            selected_result = -1;
        }
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 1.0f, 1.0f), "Filtered by: %s",
            std::filesystem::path(selected_file).filename().string().c_str());
    }

    // THREAD SAFE: Create local copy of results for rendering
    std::vector<ScanResult> local_results;
    {
        std::lock_guard<std::mutex> lock(g_scan_result_mutex);
        local_results = g_scan_results;
    }

    // Filter results for selected file
    std::vector<ScanResult> filtered_results;
    size_t total_matches_for_file = 0;

    if (!selected_file.empty()) {
        for (const auto& result : local_results) {
            if (result.filename == selected_file) {
                filtered_results.push_back(result);
                total_matches_for_file += result.GetTotalMatches();
            }
        }

        ImGui::Text("PATTERN MATCHES FOR: %s (%zu patterns)",
            std::filesystem::path(selected_file).filename().string().c_str(),
            total_matches_for_file);
    }
    else {
        filtered_results = local_results;
        ImGui::Text("PATTERN MATCHES - ALL FILES (%zu total)", GetTotalMatchCount());
    }

    // EXPORT SECTION - WITH SAVE DIALOGS
    ImGui::Separator();
    ImGui::BeginGroup();
    ImGui::Text("📊 Export for IR:");
    ImGui::SameLine();

    if (ImGui::Button("📋 CSV", ImVec2(80, 0))) {
        std::string filename = ShowSaveDialog(
            "CSV Files\0*.csv\0All Files\0*.*\0",
            "csv",
            "Export YARA Results to CSV"
        );

        if (!filename.empty()) {
            ExportToCSV(filtered_results, filename);
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("🔗 JSON", ImVec2(80, 0))) {
        std::string filename = ShowSaveDialog(
            "JSON Files\0*.json\0All Files\0*.*\0",
            "json",
            "Export YARA Results to JSON"
        );

        if (!filename.empty()) {
            ExportToJSON(filtered_results, filename);
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("📄 IR Report", ImVec2(150, 0))) {
        std::string filename = ShowSaveDialog(
            "Text Files\0*.txt\0All Files\0*.*\0",
            "txt",
            "Export Incident Response Report"
        );

        if (!filename.empty()) {
            ExportToIRReport(filtered_results, filename);
        }
    }

    if (!filtered_results.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "(%zu findings)", filtered_results.size());
    }
    ImGui::EndGroup();

    ImGui::Separator();

    // TABLE RENDERING CODE (same as before)
    if (ImGui::BeginTable("ScanResults", 6,
        ImGuiTableFlags_Borders |
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_ScrollX |
        ImGuiTableFlags_Resizable)) {

        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Rule", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Pattern ID", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Data Preview", ImGuiTableColumnFlags_WidthFixed, 200.0f);
        ImGui::TableSetupColumn("Hex Dump", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        // Render all rows
        int row_id = 0;
        for (const auto& result : filtered_results) {
            for (const auto& pattern_match : result.pattern_matches) {
                ImGui::PushID(row_id);
                ImGui::TableNextRow();

                if (selected_result == row_id) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(100, 100, 150, 100));
                }

                ImGui::TableSetColumnIndex(0);
                std::string filename = std::filesystem::path(result.filename).filename().string();
                if (ImGui::Selectable(filename.c_str(), selected_result == row_id,
                    ImGuiSelectableFlags_SpanAllColumns)) {
                    selected_result = row_id;
                }

                // Tooltip with full path
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Full path: %s\nRule: %s\nPattern: %s\nOffset: 0x%X",
                        result.filename.c_str(),
                        result.rule_name.c_str(),
                        pattern_match.pattern_id.c_str(),
                        (unsigned int)pattern_match.offset);
                }

                // RIGHT-CLICK CONTEXT MENU
                char popup_id[64];
                sprintf(popup_id, "ContextMenu_%d", row_id);

                if (ImGui::BeginPopupContextItem(popup_id)) {
                    if (ImGui::MenuItem("Copy Pattern ID")) {
                        ImGui::SetClipboardText(pattern_match.pattern_id.c_str());
                    }
                    if (ImGui::MenuItem("Copy Offset")) {
                        char offset_str[32];
                        sprintf(offset_str, "0x%X", (unsigned int)pattern_match.offset);
                        ImGui::SetClipboardText(offset_str);
                    }
                    if (ImGui::MenuItem("Copy Data Preview")) {
                        ImGui::SetClipboardText(pattern_match.data_preview.c_str());
                    }
                    if (ImGui::MenuItem("Copy Hex Dump")) {
                        ImGui::SetClipboardText(pattern_match.hex_dump.c_str());
                    }
                    if (ImGui::MenuItem("Copy Full File Path")) {
                        ImGui::SetClipboardText(result.filename.c_str());
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("Copy All Info")) {
                        char full_info[1024];
                        sprintf(full_info, "File: %s\nRule: %s\nPattern: %s\nOffset: 0x%X\nData: %s\nHex: %s",
                            result.filename.c_str(),
                            result.rule_name.c_str(),
                            pattern_match.pattern_id.c_str(),
                            (unsigned int)pattern_match.offset,
                            pattern_match.data_preview.c_str(),
                            pattern_match.hex_dump.c_str());
                        ImGui::SetClipboardText(full_info);
                    }

                    ImGui::EndPopup();
                }

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", result.rule_name.c_str());

                ImGui::TableSetColumnIndex(2);
                if (pattern_match.pattern_id.find("$string") != std::string::npos) {
                    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "%s", pattern_match.pattern_id.c_str());
                }
                else if (pattern_match.pattern_id.find("$hex") != std::string::npos) {
                    ImGui::TextColored(ImVec4(0.8f, 0.4f, 0.2f, 1.0f), "%s", pattern_match.pattern_id.c_str());
                }
                else if (pattern_match.pattern_id.find("$regex") != std::string::npos) {
                    ImGui::TextColored(ImVec4(0.2f, 0.4f, 0.8f, 1.0f), "%s", pattern_match.pattern_id.c_str());
                }
                else {
                    ImGui::Text("%s", pattern_match.pattern_id.c_str());
                }

                ImGui::TableSetColumnIndex(3);
                ImGui::Text("0x%X", (unsigned int)pattern_match.offset);

                ImGui::TableSetColumnIndex(4);
                if (!pattern_match.data_preview.empty()) {
                    ImGui::Text("%s", pattern_match.data_preview.c_str());

                    if (ImGui::IsItemHovered()) {
                        ImGui::BeginTooltip();
                        ImGui::Text("Pattern: %s", pattern_match.pattern_id.c_str());
                        ImGui::Text("Length: %zu bytes", pattern_match.length);
                        ImGui::Text("Preview: %s", pattern_match.data_preview.c_str());
                        ImGui::EndTooltip();
                    }
                }
                else {
                    ImGui::TextDisabled("[No data]");
                }

                ImGui::TableSetColumnIndex(5);
                if (!pattern_match.hex_dump.empty()) {
                    ImGui::Text("%s", pattern_match.hex_dump.c_str());

                    if (ImGui::IsItemHovered()) {
                        ImGui::BeginTooltip();
                        ImGui::Text("Full hex dump:");

                        // Show full hex dump (up to 256 bytes)
                        std::string full_hex;
                        for (size_t i = 0; i < pattern_match.data.size() && i < 256; i++) {
                            if (i > 0 && i % 16 == 0) full_hex += "\n";
                            char hex[4];
                            sprintf(hex, "%02X ", pattern_match.data[i]);
                            full_hex += hex;
                        }
                        if (pattern_match.data.size() > 256) full_hex += "\n...";

                        ImGui::Text("%s", full_hex.c_str());
                        ImGui::EndTooltip();
                    }
                }
                else {
                    ImGui::TextDisabled("[No hex]");
                }

                ImGui::PopID();
                row_id++;
            }
        }

        ImGui::EndTable();
    }

    ImGui::EndChild();
}

void RenderYARAEditorUI() {
    ImGui::Text("YARA Rule (Size : %zu , Capacity: %zu)", g_YaraBuffer.size(), g_YaraBuffer.capacity());
    ImGui::Separator();

    ImVec2 input_pos = ImGui::GetCursorScreenPos();
    DynamicTextCallbackData callback_data;
    callback_data.buffer = &g_YaraBuffer;

    ImGui::InputTextMultiline(
        "##YaraEditor",
        g_YaraBuffer.data(),
        g_YaraBuffer.capacity(),
        ImVec2(-1, -1),
        ImGuiInputTextFlags_CallbackResize | ImGuiInputTextFlags_CallbackAlways | ImGuiInputTextFlags_AllowTabInput,
        DynamicTextCallback,
        &callback_data
    );

    if (g_YaraBuffer.empty()) {
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec2 text_pos = input_pos;
        text_pos.x += 5;
        text_pos.y += 5;
        draw_list->AddText(text_pos, IM_COL32(128, 128, 128, 255), "Enter YARA rule here...");
    }


    //yaraEditor.RenderYARAEditor();
}


#ifdef _WIN32
#include <windows.h>
#include <commdlg.h>

// Windows-specific file dialog version
void save_yara_rule() {
    static std::string status_message = "";
    static float status_timer = 0.0f;

    if (ImGui::Button("Save YARA Rule")) {
        // Generate default filename with timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        char default_name[64];
        strftime(default_name, sizeof(default_name), "yara_rule_%Y%m%d_%H%M%S.yar", localtime(&time_t));

        char szFile[260];
        strcpy(szFile, default_name);

        OPENFILENAMEA ofn;
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "YARA Rules\0*.yar;*.yara\0All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.lpstrFileTitle = NULL;
        ofn.nMaxFileTitle = 0;
        ofn.lpstrInitialDir = NULL;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
        ofn.lpstrDefExt = "yar";
        ofn.lpstrTitle = "Save YARA Rule";

        if (GetSaveFileNameA(&ofn)) {
            try {
                std::string file_path = std::string(szFile);
                std::ofstream outfile(file_path, std::ios::out | std::ios::trunc);
                if (outfile.is_open()) {
                    outfile << g_YaraBuffer.c_str();
                    outfile.close();

                    status_message = "YARA rule saved successfully to: " +
                        std::filesystem::path(file_path).filename().string();
                    status_timer = 3.0f;

                    // Add to compilation output
                    compilation_output_buffer += "[SUCCESS] YARA rule saved to: " + file_path + "\n";
                }
                else {
                    status_message = "Error: Could not create/open file";
                    status_timer = 3.0f;
                }
            }
            catch (const std::exception& e) {
                status_message = "Error: " + std::string(e.what());
                status_timer = 3.0f;
            }
        }
    }

    // Display status message
    if (!status_message.empty() && status_timer > 0.0f) {
        ImVec4 color = status_message.find("Error") != std::string::npos ?
            ImVec4(1.0f, 0.4f, 0.4f, 1.0f) : ImVec4(0.4f, 1.0f, 0.4f, 1.0f);
        ImGui::TextColored(color, "%s", status_message.c_str());
        status_timer -= ImGui::GetIO().DeltaTime;
        if (status_timer <= 0.0f) {
            status_message.clear();
        }
    }
}
#endif

void RenderCompilationOutput(float compilation_height) {

    ImGui::Text("Compilation Output");
    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(60, 0))) {
        compilation_output_buffer.clear();
    }
    ImGui::SameLine();
    if (ImGui::Button("Copy All", ImVec2(120, 0))) {
        ImGui::SetClipboardText(compilation_output_buffer.c_str());
    }

    ImGui::Separator();

    // Create display buffer
    static std::string display_buffer;
    display_buffer = compilation_output_buffer;
    display_buffer.reserve(display_buffer.size() + 1024);

    // Set black background and terminal-like colors
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.1f, 0.1f, 0.1f, 1.0f));        // Black background
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.9f, 0.9f, 1.0f));           // Light gray text
    ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, ImVec4(0.3f, 0.3f, 0.7f, 0.5f));  // Blue selection

    ImGui::InputTextMultiline(
        "##CompilationOutput",
        &display_buffer[0],
        display_buffer.capacity(),
        ImVec2(-1, compilation_height),
        ImGuiInputTextFlags_ReadOnly
    );

    ImGui::PopStyleColor(3); // Pop all 3 colors


}

void RenderYARAUI() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(vp->WorkSize, ImGuiCond_Always);




    if (ImGui::Begin("YARA Scanner", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) {


        // Calculate layout dimensions
        ImVec2 content_region = ImGui::GetContentRegionAvail();
        float left_panel_ratio = 0.35f;
        float right_panel_ratio = 1.0f - left_panel_ratio;
        float button_height = 35.0f;
        float remaining_height = content_region.y - ImGui::GetCursorPosY() - 1.7 * button_height;
        float compilation_height = 180.0f;
        float main_content_height = remaining_height - compilation_height - button_height - 60.0f;
        float left_panel_width = content_region.x * left_panel_ratio - 5.0f;
        float right_panel_width = content_region.x * right_panel_ratio - 5.0f;
        // Right Panel
        float right_top_height = main_content_height * left_panel_ratio - 40.0f;
        float right_bottom_height = main_content_height * right_panel_ratio - 20.0f;




        // SELECTORS
        ImGui::BeginGroup();
        ShowFileSelector(); ImGui::SameLine();
        ShowDirectorySelector_COM(); ImGui::SameLine();
        save_yara_rule();
        ImGui::EndGroup();


        ImGui::Spacing();


        ImGui::Text("Selected YARA File : %s", g_SelectedYaraFile);
        ImGui::Text("Selected Directory: %s", g_SelectedDir);

        ImGui::Separator();



        // Left Panel
        ImGui::BeginGroup();
        ImGui::BeginChild("LeftPanel", ImVec2(left_panel_width, main_content_height), true);
        RenderYARAEditorUI();
        ImGui::EndChild();
        ImGui::EndGroup();
        ImGui::SameLine();


        ImGui::BeginGroup();
        ImGui::BeginChild("RightPanel", ImVec2(right_panel_width, main_content_height), true);
        ImGui::Text("Analysis Result"); ImGui::Separator();
        // Top right section
        ImGui::BeginChild("ResultTop", ImVec2(-1, right_top_height), true);
        float col_width = (right_panel_width - 35.0f) * 0.5f;

        RenderFileInfoSection(col_width, -1); ImGui::SameLine();
        RenderMatchDetailsSection(col_width, -1);
        ImGui::EndChild();
        //RenderPatternTableSection(-1, right_bottom_height);
        RenderPatternTableSection(-1, right_bottom_height);

        ImGui::EndChild(); // end right panel
        ImGui::EndGroup();


        ImGui::Spacing();


        // Compile and Scan
        if (ImGui::Button("Compile", ImVec2(100, button_height))) { compile_yara_rules(); } ImGui::SameLine();
        if (ImGui::Button("Scan", ImVec2(100, button_height))) { scan_directory_async(); } ImGui::SameLine();

        if (g_compiled_rules && g_scanner) ImGui::TextColored(ImVec4(0, 1, 0, 1), ":D Ready");
        else ImGui::TextColored(ImVec4(1, 1, 0, 1), "○ Not Ready");


        ImGui::SameLine();
        if (g_scan_results.size() > 0) {
            ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "| %zu Results", g_scan_results.size());
        }

        // Compilation output
        //ImGui::Text("Compilation output");
        ImGui::Spacing();
        ImGui::Separator();
        /*ImGui::BeginChild("CompilationOutput", ImVec2(-1, compilation_height), true, ImGuiWindowFlags_AlwaysVerticalScrollbar);
        ImGui::TextWrapped("%s", compilation_output_buffer.c_str());
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndChild();
        */


        RenderCompilationOutput(140.0f);

        /*
        if (ImGui::Button("Clear Output", ImVec2(150, button_height))) {
            compilation_output_buffer.clear();
        }
        */
    }
    ImGui::End();
}




void CleanupYARAX() {
    if (g_scanner) {
        yrx_scanner_destroy(g_scanner);
        g_scanner = nullptr;
    }
    if (g_compiled_rules) {
        yrx_rules_destroy(g_compiled_rules);
        g_compiled_rules = nullptr;
    }
}







int main(int, char**)
{

    // Make process DPI aware and obtain main monitor scale
    ImGui_ImplWin32_EnableDpiAwareness();
    float main_scale = ImGui_ImplWin32_GetDpiScaleForMonitor(::MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    // Create application window
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"IMGUIWITHYARAX", nullptr };


    wc.hIcon = (HICON)LoadImage(nullptr, L"YaraXGUI.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE | LR_DEFAULTSIZE);
    wc.hIconSm = (HICON)LoadImage(nullptr, L"YaraXGUI.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE | LR_DEFAULTSIZE);

    if (!wc.hIcon) {
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
    }

    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"YaraXGUI", WS_OVERLAPPEDWINDOW, 100, 100, (int)(1280 * main_scale), (int)(800 * main_scale), nullptr, nullptr, wc.hInstance, nullptr);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();
    //ImGui::StyleColorsLight();

    // Setup scaling
    ImGuiStyle& style = ImGui::GetStyle();
    style.ScaleAllSizes(main_scale);        // Bake a fixed style scale. (until we have a solution for dynamic style scaling, changing this requires resetting Style + calling this again)
    style.FontScaleDpi = main_scale;        // Set initial font scale. (using io.ConfigDpiScaleFonts=true makes this unnecessary. We leave both here for documentation purpose)

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);










    // Main loop
    bool done = false;
    while (!done)
    {
        // Poll and handle messages (inputs, window resize, etc.)
        // See the WndProc() function below for our to dispatch events to the Win32 backend.
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        // Handle window being minimized or screen locked
        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
        {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        // Handle window resize (we don't resize directly in the WM_SIZE handler)
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();



        RenderYARAUI();






        // Rendering
        ImGui::Render();
        const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        // Present
        HRESULT hr = g_pSwapChain->Present(1, 0);   // Present with vsync
        //HRESULT hr = g_pSwapChain->Present(0, 0); // Present without vsync
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

// Helper functions

bool CreateDeviceD3D(HWND hWnd)
{
    // Setup swap chain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Win32 message handler
// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
