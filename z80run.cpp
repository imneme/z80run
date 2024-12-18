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
#include <list>
#include <map>
#include <optional>
#include <format>
#include <fstream>
#include <iostream>
#include <regex>
#include <span>

class SymbolTable {
public:
    // Case insensitive comparison for map
    struct CaseInsensitiveCompare {
        bool operator()(const std::string& a, const std::string& b) const {
            return std::lexicographical_compare(
                a.begin(), a.end(),
                b.begin(), b.end(),
                [](char a, char b) { return std::toupper(a) < std::toupper(b); }
            );
        }
    };

    void load_file(const std::string& filename) {
        std::ifstream file(filename);
        if (!file) {
            throw std::runtime_error(std::format("Cannot open symbol file: {}", filename));
        }

        std::regex re(R"((\w+)\s+EQU\s+(\$?[0-9A-F]+H?))", std::regex::icase);
        std::string line;
        while (std::getline(file, line)) {
            std::smatch match;
            if (std::regex_search(line, match, re)) {
                const std::string& symbol = match[1];
                int address;
                // auto address = std::stoul(match[2], nullptr, 16);
                std::string address_str = match[2];
                if (address_str.front() == '$') {
                    address = std::stoul(address_str.substr(1), nullptr, 16);
                } else if (address_str.back() == 'H') {
                    address = std::stoul(address_str.substr(0, address_str.size() - 1), nullptr, 16);
                } else {
                    address = std::stoul(address_str, nullptr, 0);
                }
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
            } else if (offset > 1024) {
                return std::nullopt;
            }
            return std::format("{}+{}", it->second, offset);
        }
        return std::nullopt;
    }

    std::string find_symbol_or_address(uint16_t address) const {
        if (auto sym = find_symbol(address)) {
            return *sym;
        }
        return std::format("{:04x}", address);
    }

    std::optional<uint16_t> find_address(std::string_view name) const {
        // Parse symbol[+-]offset format
        std::regex offset_re(R"(([^+-]+)([-+]\d+)?)");
        std::match_results<std::string_view::const_iterator> match;
        
        if (!std::regex_match(name.begin(), name.end(), match, offset_re)) {
            return std::nullopt;
        }
        
        std::string symbol(match[1]);
        
        // Look up base symbol (case insensitive)
        auto it = by_name_.find(symbol);
        uint16_t addr;
        if (it == by_name_.end()) {
            // Try using as a numeric address
            try {
                addr = std::stoul(symbol, nullptr, 0);
            } catch (...) {
                return std::nullopt;
            }
        } else {
            addr = it->second;
        }
        
        // Handle offset if present
        if (match[2].matched) {
            std::string offset_str(match[2]);
            int offset = std::stoi(offset_str);
            addr += offset;
        }
        
        return addr;
    }

    std::string disassemble_address(uint32_t address, std::span<uint8_t> memory) const;

private:
    std::map<uint16_t, std::string> by_address_;
    std::map<std::string, uint16_t, CaseInsensitiveCompare> by_name_;
};

class EventDetector {
public:
    virtual ~EventDetector() = default;
    virtual void memory_read(uint16_t addr, uint8_t value) = 0;
    virtual void memory_write(uint16_t addr, uint8_t value) = 0;
    virtual std::optional<std::string> event() = 0;
};

class MemoryWatcher : public EventDetector {
public:
    enum class Size { Byte = 1, Word = 2, Long = 4 };

    MemoryWatcher(uint16_t addr, Size size, std::span<uint8_t> memory, SymbolTable& symbols)
        : addr_(addr), size_(size), memory_(memory), symbols_(symbols) {
        // Capture initial value
        last_value_ = fetch_value();
    }

    void memory_read(uint16_t addr, uint8_t value) override {
        check_trigger(addr);
    }

    void memory_write(uint16_t addr, uint8_t value) override {
        check_trigger(addr);
    }

    std::optional<std::string> event() override {
        if (!triggered_) {
            return std::nullopt;
        }

        triggered_ = false;
        uint32_t current = fetch_value();
        uint32_t last_value = last_value_;
        auto symbolicated = symbols_.find_symbol_or_address(addr_);
        if (current != last_value_) {
            last_value_ = current;
            switch (size_) {
                case Size::Byte:
                    return std::format("Watch {}: {:02x} -> {:02x}", 
                        symbolicated, last_value, current);
                case Size::Word:
                    return std::format("Watch {}: {:04x} -> {:04x}", 
                        symbolicated, last_value, current);
                case Size::Long:
                    return std::format("Watch {}: {:08x} -> {:08x}", 
                        symbolicated, last_value, current);
            }
        } else {
            switch (size_) {
                case Size::Byte:
                    return std::format("Watch {}: {:02x}", symbolicated, current);
                case Size::Word:
                    return std::format("Watch {}: {:04x}", symbolicated, current);
                case Size::Long:
                    return std::format("Watch {}: {:08x}", symbolicated, current);
            }
        }

        return std::nullopt;    
    }


private:
    uint32_t fetch_value() {
        uint32_t value = 0;
        for (size_t i = 0; i < static_cast<size_t>(size_); ++i) {
            value |= static_cast<uint32_t>(memory_[addr_ + i]) << (8 * i);
        }
        return value;
    }

    void check_trigger(uint16_t access_addr) {
        // Check if this access affects our watched region
        if (access_addr >= addr_ && access_addr < addr_ + static_cast<size_t>(size_)) {
            triggered_ = true;
        }
    }

    bool triggered_ = false;
    uint16_t addr_;
    Size size_;
    std::span<uint8_t> memory_;
    uint32_t last_value_;
    SymbolTable& symbols_;
};

class MemoryRangeWatcher : public EventDetector {
public:
    MemoryRangeWatcher(uint16_t start, uint16_t end, std::span<uint8_t> memory, SymbolTable& symbols)
        : start_(start), end_(end), memory_(memory), symbols_(symbols) {
        last_values_.resize(end - start + 1);
        std::copy(memory.begin() + start, memory.begin() + end + 1, last_values_.begin());
    }

    void memory_read(uint16_t addr, uint8_t value) override {
        auto change = check_change(addr);
        if (change) {
            events_.push_back(*change);
        }
    }

    void memory_write(uint16_t addr, uint8_t value) override {
        auto change = check_change(addr);
        if (change) {
            last_values_[addr - start_] = value;
            events_.push_back(*change);
        }
    }

    std::optional<std::string> event() override {
        if (events_.empty()) {
            return std::nullopt;
        }

        // Join the events with commas
        std::string result;
        bool did_first = false;
        for (const auto& event : events_) {
            if (did_first) {
                result += ", ";
            }
            result += event;
            did_first = true;
        }
        events_.clear();
        auto sym_start = symbols_.find_symbol_or_address(start_);
        auto sym_end = symbols_.find_symbol_or_address(end_);
        return std::format("Watch range {}-{}: {}", sym_start, sym_end, result);
    }

private:
    std::optional<std::string> check_change(uint16_t addr) {
        if (addr >= start_ && addr <= end_) {
            uint8_t current = memory_[addr];
            uint8_t last = last_values_[addr - start_];
            if (current != last) {
                return std::format("byte {} changed: {:02x} -> {:02x}",
                    symbols_.find_symbol_or_address(addr), last, current);
            }
        }
        return std::nullopt;
    }

    uint16_t start_;
    uint16_t end_;
    std::span<uint8_t> memory_;
    std::vector<uint8_t> last_values_;
    std::list<std::string> events_;
    SymbolTable& symbols_;
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
                return (range.flags & flag) == 0; // Flag clear means permission granted
            }
        }
        return true;  // No range found, assme permission granted
    }

    std::vector<Range> ranges_;
};

class LogOpt {
public:
    static constexpr uint32_t Instructions       = 1 << 0;
    static constexpr uint32_t MemoryReads        = 1 << 1;
    static constexpr uint32_t MemoryWrites       = 1 << 2;
    static constexpr uint32_t InstructionFetches = 1 << 3;
    static constexpr uint32_t Violations         = 1 << 4;
    static constexpr uint32_t Cycles             = 1 << 5;
    static constexpr uint32_t Most = Instructions | MemoryReads | MemoryWrites | Violations | Cycles;
    static constexpr uint32_t All = Instructions | MemoryReads | MemoryWrites | InstructionFetches | Violations | Cycles;
};

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

    void instruction_finish(uint16_t pc, const class CPU& cpu) {
        for (auto& detector : detectors_) {
            if (auto event = detector->event()) {
                log_detector_event(*event);
            }
        }
    }

    void memory_read(uint16_t addr, uint8_t value, bool is_instruction) {
        // Always check detectors, regardless of logging options
        for (auto& detector : detectors_) {
            detector->memory_read(addr, value);
        }

        if ((!is_instruction && !(options_ & LogOpt::MemoryReads))
            || (is_instruction && !(options_ & LogOpt::InstructionFetches))) {
            return;
        }
        
        if (options_ & LogOpt::Cycles) {
            std::cout << std::format("{:7}:", current_cycle_);
        }

        char code = is_instruction ? 'I' : 'R';
        auto sym = symbols_.find_symbol_or_address(addr);
        std::cout << std::format(" \t\t\t\t{} {:02x} @ {}", code, value, sym);
        std::cout << "\n";
    }

    void memory_write(uint16_t addr, uint8_t value) {
        // Always check detectors, regardless of logging options
        for (auto& detector : detectors_) {
            detector->memory_write(addr, value);
        }

        if (!(options_ & LogOpt::MemoryWrites)) {
            return;
        }

        if (options_ & LogOpt::Cycles) {
            std::cout << std::format("{:7}:", current_cycle_);
        }

        auto sym = symbols_.find_symbol_or_address(addr);
        std::cout << std::format(" \t\t\t\tW {:02x} @ {}", value, sym);
        std::cout << "\n";
    }

    void violation(std::string_view message, std::optional<uint16_t> addr = std::nullopt) {
        if (!(options_ & LogOpt::Violations)) {
            return;
        }

        if (options_ & LogOpt::Cycles) {
            std::cout << std::format("{:7}:", current_cycle_);
        }

        if (addr) {
            auto sym = symbols_.find_symbol_or_address(*addr);
            std::cout << std::format(" Violation: {} at {}\n", message, sym);
        } else {
            std::cout << std::format(" Violation: {}\n", message);
        }
    }

    void add_detector(std::unique_ptr<EventDetector> detector) {
        detectors_.push_back(std::move(detector));
    }

private:
    void log_detector_event(const std::string& message) {
        if (options_ & LogOpt::Cycles) {
            std::cout << std::format("{:7}:", current_cycle_);
        }
        std::cout << std::format(" \t\t\t\t\t{}\n", message);
    }

    uint32_t options_ = LogOpt::Most;  // Almost everything on by default
    uint32_t current_cycle_ = 0;
    const SymbolTable& symbols_;
    std::vector<std::unique_ptr<EventDetector>> detectors_;
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
            if (last_instr_pc_) {
                logger_.instruction_finish(*last_instr_pc_, *this);
            }
            last_instr_pc_ = pc - 1;
            logger_.instruction_start(pc - 1, *this);
        }
        pins_ = z80_tick(this, pins_);
        return process_memory_access();
    }

    void set_memory(std::span<uint8_t> mem) {
        memory_ = mem;
    }

    void set_pc(uint16_t addr) {
        if (last_instr_pc_) {
            logger_.instruction_finish(*last_instr_pc_, *this);
        }
        pins_ = z80_prefetch(this, addr);
    }

private:
    bool process_memory_access() {
        if (!(pins_ & Z80_MREQ)) {
            return true;
        }

        const uint16_t addr = Z80_GET_ADDR(pins_);
        if (pins_ & Z80_RD) {
            // You might think that Z80_M1 is the thing to check here, but
            // actually that only fires on the first cycle of an instruction
            // if it's a multibyte instruction, you'll be out of luck.
            bool is_instruction = addr == this->pc - 1;
            if (!is_instruction && !checker_.check_read(addr)) {
                logger_.violation("Memory read not allowed", addr);
                return false;
            } else if (is_instruction && !checker_.check_execute(addr)) {
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
    std::optional<uint16_t> last_instr_pc_;
};

// Now we can define instruction_start since we have CPU
void EventLogger::instruction_start(uint16_t pc, const CPU& cpu) {
    if (!(options_ & LogOpt::Instructions)) {
        return;
    }

    if (options_ & LogOpt::Cycles) {
        std::cout << std::format("{:7}:", current_cycle_);
    }

    auto sym = symbols_.find_symbol_or_address(pc);
    std::cout << std::format(" {:<22}\t", sym);
    
    // Disassemble the instruction
    std::cout << symbols_.disassemble_address(pc, cpu.memory()) << "\n";
}

std::string SymbolTable::disassemble_address(uint32_t address, std::span<uint8_t> memory) const {
    std::string result;
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
    DisasmContext ctx(address, memory, disasm);
    z80dasm_op(address, DisasmContext::read_byte, DisasmContext::write_char, &ctx);

    // Look for addresses in the disassembly and try to replace with symbols
    std::regex addr_re(R"(([0-9A-F]{4})[Hh])");
    std::string_view input(disasm);
    std::match_results<std::string_view::const_iterator> match;
    size_t last_pos = 0;

    while (std::regex_search(input.begin() + last_pos, input.end(), match, addr_re)) {
        result.append(input.begin() + last_pos, input.begin() + last_pos + match.position());
        uint16_t addr = std::stoul(std::string(match[1]), nullptr, 16);
        if (auto sym = find_symbol(addr)) {
            result += *sym;
        } else {
            result.append(match[0]);
        }
        last_pos += match.position() + match.length();
    }
    result.append(input.begin() + last_pos, input.end());

    return result;
}

struct Config {
    struct LoadSpec {
        std::string filename;
        uint16_t address;
    };
    struct WatchSpec {
        enum class Type { Byte, Word, Long, Range };
        Type type;
        uint16_t addr;
        uint16_t end_addr;  // Only used for Range type
    };
    std::vector<LoadSpec> files_to_load;
    uint32_t verbosity = LogOpt::Most;
    std::vector<std::tuple<uint16_t, uint16_t, uint8_t>> protections;
    std::vector<WatchSpec> watches;
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

std::pair<uint16_t,uint16_t> parse_range_or_value(std::string_view range, const SymbolTable& symbols) {
    // Parse symbol[+-]offset format
    static std::regex re(R"(\s*(0x[a-fA-F\d]+|\d+|[^\W\d]\w*(?:[-+]\d+)?)(?:\s*-\s*(0x[a-fA-F\d]+|\d+|[^\W\d]\w*(?:[-+]\d+)?))?\s*)");
    std::match_results<std::string_view::const_iterator> match;
    if (!std::regex_match(range.begin(), range.end(), match, re)) {
        throw std::runtime_error("Invalid range or value");
    }
    auto startStr = std::string(match[1]);
    auto start = symbols.find_address(startStr);
    if (!start) {
        throw std::runtime_error("Couldn't parse or resolve start address: " + startStr);
    }
    uint16_t startAddr = *start;
    uint16_t endAddr = startAddr;
    if (match[2].matched) {
        auto endStr = std::string(match[2]);
        auto end = symbols.find_address(endStr);
        if (!end) {
            throw std::runtime_error("Couldn't parse or resolve end address: " + endStr);
        }
        endAddr = *end;
    }
    if (endAddr < startAddr) {
        throw std::runtime_error("End address is before start address");
    }
    return {startAddr, endAddr};
}

Config parse_args(int argc, char* argv[], const SymbolTable& symbols) {
    Config cfg;

    for (int i = 1; i < argc; i++) {
        std::string_view arg(argv[i]);
        
        if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: z80run [options]\n"
                "Options:\n"
                "  --load file@addr  Load binary file at address\n"
                "  --start addr      Start execution at address\n"
                "  --stack addr      Set stack pointer to address\n"
                "  --protect range:flags  Protect memory range with flags\n"
                "  --watch addr      Watch byte at address\n"
                "  --watch-word addr Watch word at address\n"
                "  --watch-long addr Watch long at address\n"
                "  --watch range     Watch memory range\n"
                "  --max-cycles n    Stop after n cycles\n"
                "  --logopts flags   Set logging options\n"
                "                c - cycles\n"
                "                i - instructions\n"
                "                r - memory reads\n"
                "                w - memory writes\n"
                "                f - instruction fetches\n"
                "                v - violations\n"
                "                a - all\n"
                "                m - most (default)\n";
            std::exit(0);
        } else if (arg == "--load") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--load requires an argument");
            }
            std::string spec = argv[++i];
            
            // Parse file@addr or file@symbol
            size_t sep_pos = spec.find('@');
            if (sep_pos == std::string::npos) {
                throw std::runtime_error("--load requires @addr or @symbol");
            }
            
            std::string filename = spec.substr(0, sep_pos);
            std::string addr_spec = spec.substr(sep_pos + 1);
            uint16_t addr;
            
            if (auto sym_addr = symbols.find_address(addr_spec)) {
                addr = *sym_addr;
            } else {
                throw std::runtime_error(std::format("Unknown symbol: {}", addr_spec));
            }
            
            cfg.files_to_load.push_back({filename, addr});
        }
        else if (arg == "--start") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--start requires an argument");
            }
            std::string addr_spec = argv[++i];
            
            // Could be a hex address or a symbol
            if (auto sym_addr = symbols.find_address(addr_spec)) {
                cfg.start_address = *sym_addr;
            } else {
                throw std::runtime_error(std::format("Unknown symbol: {}", addr_spec));
            }
        }
        else if (arg == "--stack") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--stack requires an argument");
            }
            std::string addr_spec = argv[++i];
            
            if (auto sym_addr = symbols.find_address(addr_spec)) {
                cfg.stack_address = *sym_addr;
            } else {
                throw std::runtime_error(std::format("Unknown symbol: {}", addr_spec));
            }
        }
        else if (arg == "--protect") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--protect requires an argument");
            }
            std::string spec = argv[++i];
            
            // Parse addr-addr:flags format
            size_t sep_pos = spec.rfind(':');
            std::string range;
            std::string flags;
            if (sep_pos == std::string::npos) {
                range = spec;
            } else {            
                range = spec.substr(0, sep_pos);
                flags = spec.substr(sep_pos + 1);
            }

            // Test out new range parsing function
            auto [start, end] = parse_range_or_value(range, symbols);
                        
            uint8_t permissions = ConstraintChecker::NO_READ | ConstraintChecker::NO_WRITE | ConstraintChecker::NO_EXEC;
            for (char c : flags) {
                switch (c) {
                    case 'r': permissions &= ~ConstraintChecker::NO_READ; break;
                    case 'w': permissions &= ~ConstraintChecker::NO_WRITE; break;
                    case 'x': permissions &= ~ConstraintChecker::NO_EXEC; break;
                    case ' ':
                    case '\t':
                    case '\n': break; // Ignore whitespace
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
        else if (arg == "--logopts") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--logopts requires an argument");
            }
            std::string opts = argv[++i];
            uint32_t logopts = LogOpt::Most;
            for (char c : opts) {
                auto combiner = [&](uint32_t newOption) {
                    if (std::islower(c)) {
                        logopts |= newOption;
                    } else {
                        logopts &= ~newOption;
                    }
                };
                switch (std::tolower(c)) {
                    case 'c': combiner(LogOpt::Cycles); break;
                    case 'i': combiner(LogOpt::Instructions); break;
                    case 'r': combiner(LogOpt::MemoryReads); break;
                    case 'w': combiner(LogOpt::MemoryWrites); break;
                    case 'f': combiner(LogOpt::InstructionFetches); break;
                    case 'v': combiner(LogOpt::Violations); break;
                    case 'a': combiner(LogOpt::All); break;
                    case 'm': combiner(LogOpt::Most); break;
                    case ' ': // fallthrough
                    case '\t': // fallthrough
                    case '\n': break; // Ignore whitespace
                    default:
                        throw std::runtime_error(std::format("Invalid log option: {}", c));
                }
            }
            cfg.verbosity = logopts;
        }
        else if (arg == "--watch" || arg == "--watch-word" || arg == "--watch-long") {
            if (i + 1 >= argc) {
                throw std::runtime_error(std::format("{} requires an address", arg));
            }
            std::string addr_spec = argv[++i];
            uint16_t addr;

            // Could be a hex address or a symbol
            if (auto sym_addr = symbols.find_address(addr_spec)) {
                addr = *sym_addr;
            } else {
                throw std::runtime_error(std::format("Unknown symbol: {}", addr_spec));
            }

            Config::WatchSpec::Type type = Config::WatchSpec::Type::Byte;
            if (arg == "--watch-word") {
                type = Config::WatchSpec::Type::Word;
            } else if (arg == "--watch-long") {
                type = Config::WatchSpec::Type::Long;
            }
            
            cfg.watches.push_back({type, addr, 0});
        }
        else if (arg == "--watch-range") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--watch-range requires start-end addresses");
            }
            std::string range = argv[++i];
            
            // Parse start-end format
            size_t dash_pos = range.find('-');
            if (dash_pos == std::string::npos) {
                throw std::runtime_error("--watch-range requires start-end format");
            }
            
            std::string start_spec = range.substr(0, dash_pos);
            std::string end_spec = range.substr(dash_pos + 1);
            uint16_t start_addr, end_addr;
            
            // Parse start address
            if (auto sym_addr = symbols.find_address(start_spec)) {
                start_addr = *sym_addr;
            } else {
                throw std::runtime_error(std::format("Unknown symbol: {}", start_spec));
            }
            
            // Parse end address
            if (auto sym_addr = symbols.find_address(end_spec)) {
                end_addr = *sym_addr;
            } else {
                throw std::runtime_error(std::format("Unknown symbol: {}", end_spec));
            }
            
            cfg.watches.push_back({Config::WatchSpec::Type::Range, start_addr, end_addr});
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
    
    // Set up memory watches
    for (const auto& watch : cfg.watches) {
        switch (watch.type) {
            case Config::WatchSpec::Type::Byte:
                logger.add_detector(std::make_unique<MemoryWatcher>(
                    watch.addr, MemoryWatcher::Size::Byte, memory, symbols));
                break;
            case Config::WatchSpec::Type::Word:
                logger.add_detector(std::make_unique<MemoryWatcher>(
                    watch.addr, MemoryWatcher::Size::Word, memory, symbols));
                break;
            case Config::WatchSpec::Type::Long:
                logger.add_detector(std::make_unique<MemoryWatcher>(
                    watch.addr, MemoryWatcher::Size::Long, memory, symbols));
                break;
            case Config::WatchSpec::Type::Range:
                logger.add_detector(std::make_unique<MemoryRangeWatcher>(
                    watch.addr, watch.end_addr, memory, symbols));
                break;
        }
    }
    
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

    if (cfg.max_cycles && cfg.verbosity & LogOpt::Cycles) {
        std::cout << std::format("{:7}: Reached maximum cycle count ({})\n", 
            *cfg.max_cycles, *cfg.max_cycles);
    }
    
    return 0;
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
}
