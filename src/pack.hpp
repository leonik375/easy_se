#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <optional>

/* PACK: SoftEther's binary key-value serialization format.
   All integers are big-endian. Element names are null-terminated strings.

   Wire layout (from Cedar/Pack.c WriteBufStr/WriteValue):
     [uint32 num_elements]
     for each element:
       [uint32 strlen+1][strlen bytes, NO null]  ← name (WriteBufStr format)
       [uint32 type]        0=int, 1=int64, 2=data, 3=str, 4=unistr
       [uint32 num_values]
       for each value:
         int:    [uint32 value]
         int64:  [uint64 value]
         data:   [uint32 size][size bytes]
         str:    [uint32 strlen][strlen bytes, no null]
         unistr: [uint32 utf8_size][utf8_size bytes] */

class Pack {
public:
    /* Must match Cedar/Pack.h: VALUE_INT=0, VALUE_DATA=1, VALUE_STR=2, VALUE_UNISTR=3, VALUE_INT64=4 */
    enum Type : uint32_t { T_INT = 0, T_DATA = 1, T_STR = 2, T_UNISTR = 3, T_INT64 = 4 };

    struct Elem {
        Type     type;
        uint32_t ival  = 0;
        uint64_t i64val= 0;
        std::vector<uint8_t> bytes; /* used for DATA and STR */
    };

    void set_int (const std::string &name, uint32_t v);
    void set_str (const std::string &name, const std::string &s);
    void set_data(const std::string &name, const void *d, size_t len);
    void set_bool(const std::string &name, bool v) { set_int(name, v ? 1 : 0); }

    uint32_t                  get_int (const std::string &name) const;
    std::string               get_str (const std::string &name) const;
    std::vector<uint8_t>      get_data(const std::string &name) const;

    std::vector<uint8_t> serialize() const;
    static std::optional<Pack> deserialize(const uint8_t *buf, size_t len);

private:
    std::map<std::string, Elem> elems_;
};
