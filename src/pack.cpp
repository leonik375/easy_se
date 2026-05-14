#include "pack.hpp"
#include <arpa/inet.h>
#include <cstring>

/* ---- writers ---- */

static void push_u32(std::vector<uint8_t> &b, uint32_t v) {
    v = htonl(v);
    b.insert(b.end(), reinterpret_cast<uint8_t*>(&v),
                      reinterpret_cast<uint8_t*>(&v) + 4);
}

static void push_u64(std::vector<uint8_t> &b, uint64_t v) {
    push_u32(b, static_cast<uint32_t>(v >> 32));
    push_u32(b, static_cast<uint32_t>(v));
}

/* WriteBufStr wire format: uint32(strlen+1) then strlen bytes (no null written) */
static void push_name(std::vector<uint8_t> &b, const std::string &s) {
    push_u32(b, static_cast<uint32_t>(s.size() + 1));
    b.insert(b.end(), s.begin(), s.end()); /* no null */
}

static void push_bytes(std::vector<uint8_t> &b, const void *d, size_t n) {
    const auto *p = static_cast<const uint8_t*>(d);
    b.insert(b.end(), p, p + n);
}

/* ---- readers ---- */

struct Reader {
    const uint8_t *p;
    size_t         rem;

    bool ok() const { return rem != SIZE_MAX; }

    bool read(void *out, size_t n) {
        if (rem < n) { rem = SIZE_MAX; return false; }
        if (n) memcpy(out, p, n);   /* memcpy w/ n=0 and nullptr is UB */
        p += n; rem -= n;
        return true;
    }

    bool skip(size_t n) {
        if (rem < n) { rem = SIZE_MAX; return false; }
        p += n; rem -= n;
        return true;
    }

    uint32_t u32() {
        uint32_t v = 0;
        read(&v, 4);
        return ntohl(v);
    }

    uint64_t u64() {
        uint64_t hi = u32(), lo = u32();
        return (hi << 32) | lo;
    }

    /* ReadBufStr: reads uint32 len, then len-1 bytes (len includes the +1 sentinel) */
    bool name(std::string &out) {
        uint32_t len = u32();
        if (!ok() || len == 0 || len > 4096) return false;
        uint32_t str_len = len - 1;
        out.resize(str_len);
        return str_len == 0 || read(out.data(), str_len);
    }
};

/* ---- Pack methods ---- */

void Pack::set_int(const std::string &name, uint32_t v) {
    Elem e; e.type = T_INT; e.ival = v;
    elems_[name] = std::move(e);
}

void Pack::set_str(const std::string &name, const std::string &s) {
    Elem e; e.type = T_STR;
    e.bytes.assign(s.begin(), s.end()); /* no null — VALUE_STR writes strlen bytes */
    elems_[name] = std::move(e);
}

void Pack::set_data(const std::string &name, const void *d, size_t len) {
    Elem e; e.type = T_DATA;
    const auto *p = static_cast<const uint8_t*>(d);
    e.bytes.assign(p, p + len);
    elems_[name] = std::move(e);
}

uint32_t Pack::get_int(const std::string &name) const {
    auto it = elems_.find(name);
    return (it != elems_.end() && it->second.type == T_INT) ? it->second.ival : 0;
}

std::string Pack::get_str(const std::string &name) const {
    auto it = elems_.find(name);
    if (it == elems_.end() || it->second.type != T_STR) return {};
    const auto &b = it->second.bytes;
    return std::string(b.begin(), b.end());
}

std::vector<uint8_t> Pack::get_data(const std::string &name) const {
    auto it = elems_.find(name);
    if (it == elems_.end() || it->second.type != T_DATA) return {};
    return it->second.bytes;
}

std::vector<uint8_t> Pack::serialize() const {
    std::vector<uint8_t> b;
    push_u32(b, static_cast<uint32_t>(elems_.size()));
    for (const auto &[name, e] : elems_) {
        push_name(b, name);
        push_u32(b, static_cast<uint32_t>(e.type));
        push_u32(b, 1); /* num_values = 1 */
        switch (e.type) {
            case T_INT:
                push_u32(b, e.ival);
                break;
            case T_INT64:
                push_u64(b, e.i64val);
                break;
            case T_DATA:
                push_u32(b, static_cast<uint32_t>(e.bytes.size()));
                push_bytes(b, e.bytes.data(), e.bytes.size());
                break;
            case T_STR:
                /* VALUE_STR: uint32(strlen) + strlen bytes, no null */
                push_u32(b, static_cast<uint32_t>(e.bytes.size()));
                push_bytes(b, e.bytes.data(), e.bytes.size());
                break;
        }
    }
    return b;
}

std::optional<Pack> Pack::deserialize(const uint8_t *buf, size_t len) {
    Reader r{buf, len};
    uint32_t num = r.u32();
    if (!r.ok() || num > 4096) return std::nullopt;

    Pack p;
    for (uint32_t i = 0; i < num; ++i) {
        std::string name;
        if (!r.name(name)) return std::nullopt;

        Elem e;
        e.type = static_cast<Type>(r.u32());
        uint32_t nval = r.u32();
        if (!r.ok() || nval == 0 || nval > 1024) return std::nullopt;

        switch (e.type) {
            case T_INT:
                e.ival = r.u32();
                for (uint32_t j = 1; j < nval; ++j) r.u32();
                break;
            case T_INT64:
                e.i64val = r.u64();
                for (uint32_t j = 1; j < nval; ++j) r.u64();
                break;
            case T_DATA:
            case T_STR:
            case T_UNISTR: {
                /* All three: uint32(size) + size bytes per value */
                uint32_t sz = r.u32();
                if (!r.ok() || sz > 1024*1024) return std::nullopt;
                if (e.type != T_UNISTR) {
                    e.bytes.resize(sz);
                    r.read(e.bytes.data(), sz);
                } else {
                    r.skip(sz);
                }
                for (uint32_t j = 1; j < nval; ++j) {
                    uint32_t s2 = r.u32();
                    if (!r.ok() || s2 > 1024*1024) return std::nullopt;
                    r.skip(s2);
                }
                break;
            }
            default:
                /* Unknown type — can't skip, bail */
                return std::nullopt;
        }
        if (!r.ok()) return std::nullopt;
        p.elems_[name] = std::move(e);
    }
    return p;
}
