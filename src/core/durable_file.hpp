// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Small durable file writes (header-only, no link dependency):
//
//   rename_over(from, to)    rename `from` over `to`, REPLACING an existing
//                            `to` on every platform
//   replace(path, data)      write <path>.tmp (owner-only), fsync, close,
//                            rename_over(<path>.tmp, path)
//   append(path, data)       O_APPEND `data` (owner-only on create), fsync
//   create_new(path, data)   create `path` only if absent (O_EXCL,
//                            owner-only), write `data`, fsync
//   stat_exists(path, &g)    stat() the file; on POSIX also report whether
//                            any group/other permission bit is set
//
// POSIX: open(2) with O_CLOEXEC and mode 0600, a single write(2), fsync(2)
// and std::rename (= rename(2), which atomically replaces the target).
//
// Windows (MSVC CRT): there is no <unistd.h>, fsync or O_CLOEXEC, and
// std::rename refuses an existing target, so the second save of any
// tmp+rename file would fail. The equivalents used are _sopen_s with
// _O_BINARY ("\n" is written as-is, matching POSIX) and _O_NOINHERIT (the
// O_CLOEXEC analogue), _commit (FlushFileBuffers) for fsync, and
// std::filesystem::rename, which MSVC implements as
// MoveFileExW(MOVEFILE_REPLACE_EXISTING) -- the same replace-the-target
// semantics as rename(2). Windows has no POSIX mode bits: files take the
// directory's ACL, and stat_exists() never reports group/other access there.

#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdio>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <filesystem>
#include <io.h>
#include <share.h>
#else
#include <unistd.h>
#endif

namespace core::durable_file {

namespace detail {

enum class OpenMode { Truncate, Append, Exclusive };

// Returns an fd, or -1 with errno set.
inline int open_owner_only(const std::string& path, OpenMode m)
{
#if defined(_WIN32)
    int flags = _O_WRONLY | _O_CREAT | _O_BINARY | _O_NOINHERIT;
    flags |= m == OpenMode::Truncate ? _O_TRUNC : m == OpenMode::Append ? _O_APPEND : _O_EXCL;
    int fd = -1;
    const errno_t e = ::_sopen_s(&fd, path.c_str(), flags, _SH_DENYNO, _S_IREAD | _S_IWRITE);
    if (e != 0) {
        errno = e;
        return -1;
    }
    return fd;
#else
    int flags = O_WRONLY | O_CREAT | O_CLOEXEC;
    flags |= m == OpenMode::Truncate ? O_TRUNC : m == OpenMode::Append ? O_APPEND : O_EXCL;
    return ::open(path.c_str(), flags, 0600);
#endif
}

// One write call; true only when every byte was written.
inline bool write_once(int fd, const std::string& data)
{
#if defined(_WIN32)
    if (data.size() > static_cast<std::size_t>(INT_MAX)) return false;
    return ::_write(fd, data.data(), static_cast<unsigned int>(data.size())) ==
           static_cast<int>(data.size());
#else
    return ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
#endif
}

inline bool sync_fd(int fd)
{
#if defined(_WIN32)
    return ::_commit(fd) == 0;
#else
    return ::fsync(fd) == 0;
#endif
}

inline void close_fd(int fd)
{
#if defined(_WIN32)
    ::_close(fd);
#else
    ::close(fd);
#endif
}

} // namespace detail

inline bool rename_over(const std::string& from, const std::string& to)
{
#if defined(_WIN32)
    std::error_code ec;
    std::filesystem::rename(from, to, ec);
    return !ec;
#else
    return std::rename(from.c_str(), to.c_str()) == 0;
#endif
}

inline bool replace(const std::string& path, const std::string& data)
{
    const std::string tmp = path + ".tmp";
    int fd = detail::open_owner_only(tmp, detail::OpenMode::Truncate);
    if (fd < 0) return false;
    bool ok = detail::write_once(fd, data);
    ok = detail::sync_fd(fd) && ok;
    detail::close_fd(fd);
    return ok && rename_over(tmp, path);
}

inline bool append(const std::string& path, const std::string& data)
{
    int fd = detail::open_owner_only(path, detail::OpenMode::Append);
    if (fd < 0) return false;
    bool ok = detail::write_once(fd, data);
    ok = detail::sync_fd(fd) && ok;
    detail::close_fd(fd);
    return ok;
}

// 0 on success; the errno of the failed create (> 0, EEXIST when `path`
// already exists); -1 when the write or fsync failed (the file stays).
inline int create_new(const std::string& path, const std::string& data)
{
    int fd = detail::open_owner_only(path, detail::OpenMode::Exclusive);
    if (fd < 0) return errno > 0 ? errno : EIO;
    bool ok = detail::write_once(fd, data);
    ok = detail::sync_fd(fd) && ok;
    detail::close_fd(fd);
    return ok ? 0 : -1;
}

inline bool stat_exists(const std::string& path, bool* group_other_access = nullptr)
{
#if defined(_WIN32)
    struct _stat64 st{};
    if (::_stat64(path.c_str(), &st) != 0) return false;
    if (group_other_access) *group_other_access = false;
#else
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return false;
    if (group_other_access) *group_other_access = (st.st_mode & 077) != 0;
#endif
    return true;
}

} // namespace core::durable_file
