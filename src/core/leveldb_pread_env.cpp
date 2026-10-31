// SPDX-License-Identifier: AGPL-3.0-or-later
// Built with -fno-rtti (src/core/CMakeLists.txt): LevelDB is, and these
// classes derive from its classes, whose typeinfo it then does not provide.
#include "leveldb_pread_env.hpp"

#if defined(_WIN32)

namespace core {
leveldb::Env* leveldb_pread_env() { return nullptr; }
} // namespace core

#else

#include <leveldb/env.h>
#include <leveldb/slice.h>
#include <leveldb/status.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

namespace core {

namespace {

class PreadFile final : public leveldb::RandomAccessFile {
public:
    PreadFile(std::string name, int fd) : m_name(std::move(name)), m_fd(fd) {}
    ~PreadFile() override { ::close(m_fd); }

    leveldb::Status Read(uint64_t offset, size_t n, leveldb::Slice* result, char* scratch) const override
    {
        size_t got = 0;
        while (got < n) {
            const ssize_t r = ::pread(m_fd, scratch + got, n - got, static_cast<off_t>(offset + got));
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                const int err = errno;
                *result = leveldb::Slice(scratch, got);
                return leveldb::Status::IOError(m_name, std::strerror(err));
            }
            if (r == 0)
                break;  // end of file: a short read, as LevelDB's own
            got += static_cast<size_t>(r);
        }
        *result = leveldb::Slice(scratch, got);
        return leveldb::Status::OK();
    }

private:
    std::string m_name;
    int         m_fd;
};

class PreadEnv final : public leveldb::EnvWrapper {
public:
    PreadEnv() : leveldb::EnvWrapper(leveldb::Env::Default()) {}

    leveldb::Status NewRandomAccessFile(const std::string& fname, leveldb::RandomAccessFile** result) override
    {
        const int fd = ::open(fname.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            const int err = errno;
            *result = nullptr;
            return err == ENOENT ? leveldb::Status::NotFound(fname, std::strerror(err))
                                 : leveldb::Status::IOError(fname, std::strerror(err));
        }
        *result = new PreadFile(fname, fd);
        return leveldb::Status::OK();
    }
};

} // namespace

leveldb::Env* leveldb_pread_env()
{
    static PreadEnv* env = new PreadEnv();  // never destroyed, as Env::Default()
    return env;
}

} // namespace core

#endif
