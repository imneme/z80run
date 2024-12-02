/*
 * A C++ implementation of a Z80 program runner with memory protection and
 * event logging.
 *
 * The hard work of running Z80 instructions and disassembling them is done 
 * by `z80.h` and `z80dasm.h` from Andre Weissflog's Chips library.
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2024 Melissa E. O'Neill
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#define CHIPS_IMPL
#define CHIPS_UTIL_IMPL
#include "z80.h"
#include "z80dasm.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <optional>
#include <format>
#include <fstream>
#include <iostream>
#include <regex>
#include <span>

class SymbolTable {
public:
    void load_file(const std::string& filename) {
        std::ifstream file(filename);
        if (!file) {
            throw std::runtime_error(std::format("Cannot open symbol file: {}", filename));
        }

        std::regex re(R"((\w+)\s+EQU\s+([0-9A-F]+)H)");
        std::string line;
        while (std::getline(file, line)) {
            std::smatch match;
            if (std::regex_search(line, match, re)) {
                const std::string& symbol = match[1];
                auto address = std::stoul(match[2], nullptr, 16);
                by_address_[address] = symbol;
                by_name_[symbol] = address;
            }
        }
    }

    std::optional<std::string> find_symbol(uint16_t address) const {
        auto it = by_address_.lower_bound(address);
        if (it != by_address_.begin() && (it == by_address_.end() || it->first > address)) {
            --it;
        }
        if (it != by_address_.end()) {
            ssize_t offset = address - it->first;
            if (offset == 0) {
                return it->second;
            } else if (offset < -128) {
                return std::nullopt;
            } else if (offset < 0) {
                return std::format("{}{}", it->second, offset);
            }
            return std::format("{}+{}", it->second, offset);
        }
        return std::nullopt;
    }

    std::optional<uint16_t> find_address(std::string_view name) const {
        // TODO: Case insensitive lookup
        auto it = by_name_.find(std::string(name));
        if (it != by_name_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

private:
    std::map<uint16_t, std::string> by_address_;
    std::map<std::string, uint16_t> by_name_;
};

class ConstraintChecker {
public:
    static constexpr uint8_t NO_READ = 1;
    static constexpr uint8_t NO_WRITE = 2;
    static constexpr uint8_t NO_EXEC = 4;

    void add_range(uint16_t start, uint16_t end, uint8_t protection) {
        ranges_.push_back({start, end, protection});
    }

    bool check_read(uint16_t addr) const {
        return check_permission(addr, NO_READ);
    }

    bool check_write(uint16_t addr) const {
        return check_permission(addr, NO_WRITE);
    }

    bool check_execute(uint16_t addr) const {
        return check_permission(addr, NO_EXEC);
    }

private:
    struct Range {
        uint16_t start;
        uint16_t end;
        uint8_t flags;  // What's allowed in this range
    };

    bool check_permission(uint16_t addr, uint8_t flag) const {
        for (const auto& range : ranges_) {
            if (addr >= range.start && addr <= range.end) {
                return (range.flags & flag) != 0;  // Permission granted if flag is set
            }
        }
        return false;  // No range found = no permissions
    }

    std::vector<Range> ranges_;
};

enum class LogOpt : uint32_t {
    Instructions = 1 << 0,
    MemoryReads  = 1 << 1,
    MemoryWrites = 1 << 2,
    Violations   = 1 << 3,
    Cycles       = 1 << 4,
    All = Instructions | MemoryReads | MemoryWrites | Violations | Cycles
};

inline LogOpt operator|(LogOpt a, LogOpt b) {
    return static_cast<LogOpt>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

class EventLogger {
public:

    EventLogger(const SymbolTable& symbols) : symbols_(symbols) {}

    void set_verbosity(uint32_t flags) {
        options_ = flags;
    }

    void cycle_count(uint32_t count) {
        current_cycle_ = count;
    }

    void instruction_start(uint16_t pc, const class CPU& cpu);  // Defined after CPU

    void memory_read(uint16_t addr, uint8_t value, bool is_instruction) {
        if (!is_instruction && !(options_ & static_cast<uint32_t>(LogOpt::MemoryReads))) {
            return;
        }
        
        if (options_ & static_cast<uint32_t>(LogOpt::Cycles)) {
            std::cout << std::format("{:7}:", current_cycle_);
        }

        if (auto sym = symbols_.find_symbol(addr)) {
            std::cout << std::format(" \t\tR {:02x} @ {} ", value, *sym);
        } else {
            std::cout << std::format(" \t\tR {:02x} @ {:04x}", value, addr);
        }
        std::cout << "\n";
    }

    void memory_write(uint16_t addr, uint8_t value) {
        if (!(options_ & static_cast<uint32_t>(LogOpt::MemoryWrites))) {
            return;
        }

        if (options_ & static_cast<uint32_t>(LogOpt::Cycles)) {
            std::cout << std::format("{:7}:", current_cycle_);
        }

        if (auto sym = symbols_.find_symbol(addr)) {
            std::cout << std::format(" \t\tW {:02x} @ {} ", value, *sym);
        } else {
            std::cout << std::format(" \t\tW {:02x} @ {:04x}", value, addr);
        }
        std::cout << "\n";
    }

    void violation(std::string_view message, std::optional<uint16_t> addr = std::nullopt) {
        if (!(options_ & static_cast<uint32_t>(LogOpt::Violations))) {
            return;
        }

        if (options_ & static_cast<uint32_t>(LogOpt::Cycles)) {
            std::cout << std::format("{:7}:", current_cycle_);
        }

        if (addr) {
            if (auto sym = symbols_.find_symbol(*addr)) {
                std::cout << std::format(" Violation: {} at {}\n", message, *sym);
            } else {
                std::cout << std::format(" Violation: {} at {:04x}\n", message, *addr);
            }
        } else {
            std::cout << std::format(" Violation: {}\n", message);
        }
    }

private:
    uint32_t options_ = static_cast<uint32_t>(LogOpt::All);  // Everything on by default
    uint32_t current_cycle_ = 0;
    const SymbolTable& symbols_;
};

class CPU : public z80_t {
public:
    std::span<uint8_t> memory() const { return memory_; }

    CPU(EventLogger& logger, ConstraintChecker& checker) 
        : logger_(logger), checker_(checker) {
        pins_ = z80_init(this);
    }

    bool step() {
        if (z80_opdone(this)) {
            logger_.instruction_start(pc - 1, *this);
        }
        pins_ = z80_tick(this, pins_);
        return process_memory_access();
    }

    void set_memory(std::span<uint8_t> mem) {
        memory_ = mem;
    }

    void set_pc(uint16_t addr) {
        pins_ = z80_prefetch(this, addr);
    }

private:
    bool process_memory_access() {
        if (!(pins_ & Z80_MREQ)) {
            return true;
        }

        const uint16_t addr = Z80_GET_ADDR(pins_);
        if (pins_ & Z80_RD) {
            if (!checker_.check_read(addr)) {
                logger_.violation("Memory read not allowed", addr);
                return false;
            }
            bool is_instruction = (pins_ & Z80_M1) != 0;
            if (is_instruction && !checker_.check_execute(addr)) {
                logger_.violation("Instruction fetch not allowed", addr);
                return false;
            }
            Z80_SET_DATA(pins_, memory_[addr]);
            logger_.memory_read(addr, memory_[addr], is_instruction);
        }
        else if (pins_ & Z80_WR) {
            if (!checker_.check_write(addr)) {
                logger_.violation("Memory write not allowed", addr);
                return false;
            }
            uint8_t data = Z80_GET_DATA(pins_);
            memory_[addr] = data;
            logger_.memory_write(addr, data);
        }
        return true;
    }

    uint64_t pins_;
    EventLogger& logger_;
    ConstraintChecker& checker_;
    std::span<uint8_t> memory_;
};

// Now we can define instruction_start since we have CPU
void EventLogger::instruction_start(uint16_t pc, const CPU& cpu) {
    if (!(options_ & static_cast<uint32_t>(LogOpt::Instructions))) {
        return;
    }

    if (auto sym = symbols_.find_symbol(pc)) {
        std::cout << std::format("{:<10}\t", *sym);
    } else {
        std::cout << std::format("{:04x}      \t", pc);
    }
    
    // Disassemble the instruction
    class DisasmContext {
    public:
        uint16_t pc;
        std::span<uint8_t> mem;
        std::string& output;

        DisasmContext(uint16_t pc_, std::span<uint8_t> mem_, std::string& output_)
            : pc(pc_), mem(mem_), output(output_) {}

        static uint8_t read_byte(void* user_data) {
            auto* ctx = static_cast<DisasmContext*>(user_data);
            return ctx->mem[ctx->pc++];
        }

        static void write_char(char c, void* user_data) {
            auto* ctx = static_cast<DisasmContext*>(user_data);
            ctx->output += c;
        }
    };

    std::string disasm;
    DisasmContext ctx(pc, cpu.memory(), disasm);
    z80dasm_op(pc, DisasmContext::read_byte, DisasmContext::write_char, &ctx);

    // Look for addresses in the disassembly and try to replace with symbols
    std::regex addr_re(R"(([0-9A-F]{4})[Hh])");
    std::string result;
    std::string_view input(disasm);
    std::match_results<std::string_view::const_iterator> match;
    size_t last_pos = 0;

    while (std::regex_search(input.begin() + last_pos, input.end(), match, addr_re)) {
        result.append(input.begin() + last_pos, input.begin() + last_pos + match.position());
        uint16_t addr = std::stoul(std::string(match[1]), nullptr, 16);
        if (auto sym = symbols_.find_symbol(addr)) {
            result += *sym;
        } else {
            result.append(match[0]);
        }
        last_pos += match.position() + match.length();
    }
    result.append(input.begin() + last_pos, input.end());

    std::cout << result << "\n";
}

struct Config {
    struct LoadSpec {
        std::string filename;
        uint16_t address;
    };
    std::vector<LoadSpec> files_to_load;
    uint32_t verbosity = 0xFFFFFFFF;  // Everything on by default
    std::vector<std::tuple<uint16_t, uint16_t, uint8_t>> protections;
    std::optional<uint16_t> start_address;
    std::optional<uint16_t> stack_address;
    std::optional<uint32_t> max_cycles;
};

void load_binary(const std::string& filename, std::span<uint8_t> memory, size_t offset) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error(std::format("Cannot open binary file: {}", filename));
    }
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (size > memory.size() - offset) {
        throw std::runtime_error(std::format("File too large: {} bytes", size));
    }
    
    file.read(reinterpret_cast<char*>(memory.data() + offset), size);
}

Config parse_args(int argc, char* argv[], const SymbolTable& symbols) {
    Config cfg;

    for (int i = 1; i < argc; i++) {
        std::string_view arg(argv[i]);
        
        if (arg == "--load") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--load requires an argument");
            }
            std::string spec = argv[++i];
            
            // Parse file@addr or file:symbol
            size_t sep_pos = spec.find_first_of("@:");
            if (sep_pos == std::string::npos) {
                throw std::runtime_error("--load requires @addr or :symbol");
            }
            
            std::string filename = spec.substr(0, sep_pos);
            std::string addr_spec = spec.substr(sep_pos + 1);
            uint16_t addr;
            
            if (spec[sep_pos] == '@') {
                // Parse hex address
                addr = std::stoul(addr_spec, nullptr, 0);
            } else {
                // Look up symbol
                if (auto sym_addr = symbols.find_address(addr_spec)) {
                    addr = *sym_addr;
                } else {
                    throw std::runtime_error(std::format("Unknown symbol: {}", addr_spec));
                }
            }
            
            cfg.files_to_load.push_back({filename, addr});
        }
        else if (arg == "--start") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--start requires an argument");
            }
            std::string addr_spec = argv[++i];
            
            // Could be a hex address or a symbol
            try {
                cfg.start_address = std::stoul(addr_spec, nullptr, 0);
            } catch (const std::exception&) {
                // Not a number, try as symbol
                if (auto sym_addr = symbols.find_address(addr_spec)) {
                    cfg.start_address = *sym_addr;
                } else {
                    throw std::runtime_error(std::format("Unknown symbol: {}", addr_spec));
                }
            }
        }
        else if (arg == "--stack") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--stack requires an argument");
            }
            std::string addr_spec = argv[++i];
            
            // Could be a hex address or a symbol
            try {
                cfg.stack_address = std::stoul(addr_spec, nullptr, 0);
            } catch (const std::exception&) {
                // Not a number, try as symbol
                if (auto sym_addr = symbols.find_address(addr_spec)) {
                    cfg.stack_address = *sym_addr;
                } else {
                    throw std::runtime_error(std::format("Unknown symbol: {}", addr_spec));
                }
            }
        }
        else if (arg == "--protect") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--protect requires an argument");
            }
            std::string spec = argv[++i];
            
            // Parse addr-addr:flags format
            size_t sep_pos = spec.find(':');
            if (sep_pos == std::string::npos) {
                throw std::runtime_error("--protect requires :flags");
            }
            
            std::string range = spec.substr(0, sep_pos);
            std::string flags = spec.substr(sep_pos + 1);
            
            size_t dash_pos = range.find('-');
            if (dash_pos == std::string::npos) {
                throw std::runtime_error("--protect requires addr-addr range");
            }
            
            uint16_t start = std::stoul(range.substr(0, dash_pos), nullptr, 0);
            uint16_t end = std::stoul(range.substr(dash_pos + 1), nullptr, 0);
            
            uint8_t permissions = 0;
            for (char c : flags) {
                switch (c) {
                    case 'r': permissions |= ConstraintChecker::NO_READ; break;
                    case 'w': permissions |= ConstraintChecker::NO_WRITE; break;
                    case 'x': permissions |= ConstraintChecker::NO_EXEC; break;
                    default:
                        throw std::runtime_error(std::format("Invalid permission flag: {}", c));
                }
            }
            
            cfg.protections.emplace_back(start, end, permissions);
        }
        else if (arg == "--max-cycles") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--max-cycles requires an argument");
            }
            std::string cycles_str = argv[++i];
            try {
                cfg.max_cycles = std::stoul(cycles_str);
            } catch (const std::exception&) {
                throw std::runtime_error(std::format("Invalid number of cycles: {}", cycles_str));
            }
        }
    }
    
    return cfg;
}

int main(int argc, char* argv[]) try {
    SymbolTable symbols;
    
    // First pass: load any symbol files for --load .bin files
    for (int i = 1; i < argc; i++) {
        if (std::string_view(argv[i]) == "--load" && i + 1 < argc) {
            std::string spec = argv[i + 1];
            size_t sep_pos = spec.find_first_of("@:");
            if (sep_pos != std::string::npos) {
                std::string filename = spec.substr(0, sep_pos);
                if (filename.ends_with(".bin")) {
                    std::string symfile = filename.substr(0, filename.length() - 4) + ".sym";
                    try {
                        symbols.load_file(symfile);
                    } catch (const std::exception& e) {
                        std::cerr << "Warning: " << e.what() << "\n";
                    }
                }
            }
        }
    }
    
    // Now parse the rest of the arguments
    Config cfg = parse_args(argc, argv, symbols);
    
    // Set up our system
    std::vector<uint8_t> memory(1 << 16);  // 64K
    EventLogger logger(symbols);
    logger.set_verbosity(cfg.verbosity);
    
    ConstraintChecker checker;
    for (const auto& [start, end, protection] : cfg.protections) {
        checker.add_range(start, end, protection);
    }
    
    CPU cpu(logger, checker);
    cpu.set_memory(memory);
    
    // Load all the binary files
    uint16_t start_addr = 0;
    for (const auto& spec : cfg.files_to_load) {
        load_binary(spec.filename, memory, spec.address);
        if (!cfg.start_address && start_addr == 0) {
            // First loaded file sets start address if not specified
            start_addr = spec.address;
        }
    }
    
    // Override with explicit start address if given
    if (cfg.start_address) {
        start_addr = *cfg.start_address;
    }
    
    // Set up stack pointer
    if (!cfg.stack_address) {
        // Try some common symbols
        for (const char* sym : {"InitialSP", "STACK", "StackStart", "StackBase"}) {
            if (auto addr = symbols.find_address(sym)) {
                cfg.stack_address = *addr;
                break;
            }
        }
    }
    if (cfg.stack_address) {
        cpu.sp = *cfg.stack_address;
    }

    // Initialize PC
    cpu.set_pc(start_addr);
    
    // Run until we hit a violation or max cycles
    for (uint32_t cycles = 0; !cfg.max_cycles || cycles < *cfg.max_cycles; cycles++) {
        logger.cycle_count(cycles);
        if (!cpu.step()) {
            return 1;
        }
    }

    if (cfg.max_cycles && cfg.verbosity & static_cast<uint32_t>(LogOpt::Cycles)) {
        std::cout << std::format("{:7}: Reached maximum cycle count ({})\n", 
            *cfg.max_cycles, *cfg.max_cycles);
    }
    
    return 0;
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
}
