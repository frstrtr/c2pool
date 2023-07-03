#include <iostream>
#include "response_sender.h"

beast::string_view mime_type(beast::string_view path)
{
    using beast::iequals;
    auto const ext = [&path]
    {
        auto const pos = path.rfind(".");
        if(pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();
    if(iequals(ext, ".htm"))  return "text/html";
    if(iequals(ext, ".html")) return "text/html";
    if(iequals(ext, ".php"))  return "text/html";
    if(iequals(ext, ".css"))  return "text/css";
    if(iequals(ext, ".txt"))  return "text/plain";
    if(iequals(ext, ".js"))   return "application/javascript";
    if(iequals(ext, ".json")) return "application/json";
    if(iequals(ext, ".xml"))  return "application/xml";
    if(iequals(ext, ".swf"))  return "application/x-shockwave-flash";
    if(iequals(ext, ".flv"))  return "video/x-flv";
    if(iequals(ext, ".png"))  return "image/png";
    if(iequals(ext, ".jpe"))  return "image/jpeg";
    if(iequals(ext, ".jpeg")) return "image/jpeg";
    if(iequals(ext, ".jpg"))  return "image/jpeg";
    if(iequals(ext, ".gif"))  return "image/gif";
    if(iequals(ext, ".bmp"))  return "image/bmp";
    if(iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
    if(iequals(ext, ".tiff")) return "image/tiff";
    if(iequals(ext, ".tif"))  return "image/tiff";
    if(iequals(ext, ".svg"))  return "image/svg+xml";
    if(iequals(ext, ".svgz")) return "image/svg+xml";
    return "application/text";
}

std::list<std::string> split(const std::string &str, char delimiter)
{
    std::list<std::string> parts;
    const std::string& sv(str);
    size_t pos = 0;
    while (pos < sv.length()) {
        auto next_pos = sv.find(delimiter, pos);
        if (next_pos == std::string::npos) {
            next_pos = sv.length();
        }
        parts.push_back(sv.substr(pos, next_pos - pos));
        pos = next_pos + 1;
    }
    return parts;
}

UrlData parse_url(const std::string &url)
{
    UrlData result;
    result.full_path = split(url, '?').front();

    result.path = split(url, '/');
    result.path.pop_front();

    if (result.path.empty())
        return result;

    std::string last(result.path.back());

    auto query_line = split(last, '?');
    if (!query_line.front().empty())
    {
        auto v = query_line.front();
        result.path.back() = v;
    }
    query_line.pop_front();

    if (query_line.empty())
        return result;

    auto only_query = split(query_line.back(), '&');
    for (const auto& v: only_query)
    {
        auto del_pos = v.find('=');
        if (del_pos != std::string::npos)
        {
            auto key = v.substr(0, del_pos);
            auto value = v.substr(del_pos + 1);
            result.query[key] = value;
        }
    }

    return result;
}
