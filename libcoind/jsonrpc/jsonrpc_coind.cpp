#include "jsonrpc_coind.h"


UniValue coind::JSONRPC_Coind::_request(const char *method_name)
{
	char* request_body = new char[strlen(req_format) + strlen(method_name) + 2 + 1];
	sprintf(request_body, req_format, method_name, "[]");
	req.body() = request_body;
	req.prepare_payload();
	http::write(stream, req);

	beast::flat_buffer buffer;
	boost::beast::http::response<boost::beast::http::dynamic_body> res;
	boost::beast::http::read(stream, buffer, res);
	return res;
}
